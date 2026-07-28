#!/usr/bin/env bash
# pg-backup: encrypted logical PostgreSQL backups to S3, plus the restore
# drill driver (PG_BACKUP_MODE=restore) used by the monthly recovery test.
#
# Backup mode is a tick daemon (cvm-ingress renewal_daemon idiom): every
# BACKUP_TICK_SECONDS it evaluates whether a run is owed (manual trigger
# marker, schedule cycle, or soak interval), gates on Patroni leadership,
# takes the S3 lock, and streams pg_dump | openssl | aws s3 cp for every
# non-template database plus the globals dump. The manifest is uploaded last;
# its presence is the completeness contract.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "$SCRIPT_DIR/lib/log.sh"
source "$SCRIPT_DIR/lib/s3.sh"
source "$SCRIPT_DIR/lib/lock.sh"
source "$SCRIPT_DIR/lib/pg.sh"
source "$SCRIPT_DIR/lib/pipeline.sh"
source "$SCRIPT_DIR/lib/manifest.sh"
source "$SCRIPT_DIR/lib/metrics.sh"

# ---------------------------------------------------------------------------
# Cycle model (pure functions — covered by bats).
#
# A scheduled run is owed iff the UTC clock has passed BACKUP_SCHEDULE_UTC
# and control/latest.json's last_scheduled_cycle is not today's cycle key.
# This is restart-proof and self-backfilling: a node that was down at 02:30
# runs as soon as it comes back, and a manual 01:00 backup does not suppress
# the nightly (manual runs never advance last_scheduled_cycle).
# ---------------------------------------------------------------------------

cycle_key_for() {
    date -u -d "@$1" +%F
}

# schedule_passed <epoch> <HH:MM> → 0 if the UTC time-of-day has reached HH:MM
schedule_passed() {
    local now_epoch="$1" schedule="$2"
    local now_hm
    now_hm=$(date -u -d "@${now_epoch}" +%H:%M)
    [[ "$now_hm" == "$schedule" || "$now_hm" > "$schedule" ]]
}

# cycle_owed <epoch> <HH:MM> <last_scheduled_cycle> → prints yes|no
cycle_owed() {
    local now_epoch="$1" schedule="$2" last_cycle="$3"
    if ! schedule_passed "$now_epoch" "$schedule"; then
        echo "no"
        return 0
    fi
    if [[ "$last_cycle" == "$(cycle_key_for "$now_epoch")" ]]; then
        echo "no"
    else
        echo "yes"
    fi
}

# interval_owed <epoch> <last_completed_epoch|""> <interval_s> → prints yes|no
interval_owed() {
    local now_epoch="$1" last_completed="$2" interval="$3"
    if [[ -z "$last_completed" ]]; then
        echo "yes"
        return 0
    fi
    if (( now_epoch - last_completed >= interval )); then
        echo "yes"
    else
        echo "no"
    fi
}

# infer_env_name <bucket> → prod|staging|unknown. The bucket name is part of
# the attested env surface (nearai-postgres-backups-{prod,staging}), so the
# manifest's cluster/env fields need no extra env var to be correct;
# BACKUP_ENV_NAME remains an explicit override (e2e uses it).
infer_env_name() {
    case "$1" in
        *-prod) echo "prod" ;;
        *-staging) echo "staging" ;;
        *) echo "unknown" ;;
    esac
}

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

validate_backup_env() {
    local missing=0 var
    for var in BACKUP_S3_BUCKET BACKUP_AWS_ACCESS_KEY_ID BACKUP_AWS_SECRET_ACCESS_KEY; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Required environment variable $var is not set"
            missing=1
        fi
    done
    if [[ "$missing" -eq 1 ]]; then
        exit 1
    fi

    export BACKUP_ENABLED="${BACKUP_ENABLED:-true}"
    export BACKUP_AWS_REGION="${BACKUP_AWS_REGION:-us-west-2}"
    export BACKUP_KEY_PATH="${BACKUP_KEY_PATH:-/postgres-backup/enc-v1}"
    export BACKUP_KEY_SOURCE="${BACKUP_KEY_SOURCE:-dstack}"
    export BACKUP_SCHEDULE_UTC="${BACKUP_SCHEDULE_UTC:-02:30}"
    export BACKUP_INTERVAL_SECONDS="${BACKUP_INTERVAL_SECONDS:-}"
    export BACKUP_TICK_SECONDS="${BACKUP_TICK_SECONDS:-60}"
    export BACKUP_JITTER_SECONDS="${BACKUP_JITTER_SECONDS:-300}"
    export BACKUP_HEARTBEAT_SECONDS="${BACKUP_HEARTBEAT_SECONDS:-300}"
    export BACKUP_LOCK_TTL_SECONDS="${BACKUP_LOCK_TTL_SECONDS:-1800}"
    export BACKUP_LOCK_RENEW_SECONDS="${BACKUP_LOCK_RENEW_SECONDS:-300}"
    export BACKUP_RETRY_MAX="${BACKUP_RETRY_MAX:-2}"
    export BACKUP_RETRY_DELAY_SECONDS="${BACKUP_RETRY_DELAY_SECONDS:-900}"
    export BACKUP_RUN_TIMEOUT_SECONDS="${BACKUP_RUN_TIMEOUT_SECONDS:-5400}"
    export BACKUP_MIN_FREE_TMP_MB="${BACKUP_MIN_FREE_TMP_MB:-8}"
    export BACKUP_EXCLUDE_DATABASES="${BACKUP_EXCLUDE_DATABASES:-}"
    export BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
    export BACKUP_PG_HOST="${BACKUP_PG_HOST:-patroni}"
    export BACKUP_PG_PORT="${BACKUP_PG_PORT:-5432}"
    export BACKUP_PATRONI_HOST="${BACKUP_PATRONI_HOST:-$BACKUP_PG_HOST}"
    export BACKUP_PATRONI_PORT="${BACKUP_PATRONI_PORT:-8008}"
    export BACKUP_METRICS_PORT="${BACKUP_METRICS_PORT:-9464}"
    export BACKUP_CLUSTER_NAME="${BACKUP_CLUSTER_NAME:-postgres}"
    export BACKUP_ENV_NAME="${BACKUP_ENV_NAME:-$(infer_env_name "$BACKUP_S3_BUCKET")}"

    export AWS_ACCESS_KEY_ID="$BACKUP_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$BACKUP_AWS_SECRET_ACCESS_KEY"
    export AWS_DEFAULT_REGION="$BACKUP_AWS_REGION"
    export S3_BUCKET="$BACKUP_S3_BUCKET"

    MEMBER_HOST=$(cat /setup/actual_hostname 2>/dev/null || hostname)
    export MEMBER_HOST

    log_info "Configuration:"
    log_info "  BACKUP_ENABLED=$BACKUP_ENABLED"
    log_info "  BACKUP_S3_BUCKET=$BACKUP_S3_BUCKET"
    log_info "  BACKUP_SCHEDULE_UTC=$BACKUP_SCHEDULE_UTC"
    log_info "  BACKUP_INTERVAL_SECONDS=${BACKUP_INTERVAL_SECONDS:-<schedule mode>}"
    log_info "  BACKUP_KEY_PATH=$BACKUP_KEY_PATH (source: $BACKUP_KEY_SOURCE)"
    log_info "  BACKUP_PG_HOST=$BACKUP_PG_HOST:$BACKUP_PG_PORT (patroni: $BACKUP_PATRONI_HOST:$BACKUP_PATRONI_PORT)"
    log_info "  MEMBER_HOST=$MEMBER_HOST"
}

# ---------------------------------------------------------------------------
# One backup run: enumerate DBs, snapshot-consistent counts, streamed dumps,
# globals, manifest-last, latest.json.
# ---------------------------------------------------------------------------

run_backup_once() {
    local trigger="$1"

    local backup_id started_at start_epoch deadline
    backup_id="$(date -u +%FT%H%MZ)-$(openssl rand -hex 3)"
    started_at=$(date -u +%FT%TZ)
    start_epoch=$(date +%s)
    deadline=$(( start_epoch + BACKUP_RUN_TIMEOUT_SECONDS ))
    log_info "Backup ${backup_id} starting (trigger: ${trigger})"

    fetch_encryption_key "$BACKUP_KEY_PATH" || return 1

    local tmp
    tmp=$(mktemp -d /run/backup/run.XXXXXX) || return 1
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN

    local free_mb
    free_mb=$(df -Pm /run/backup | awk 'NR==2 {print $4}')
    if [[ ! "$free_mb" =~ ^[0-9]+$ ]] || (( free_mb < BACKUP_MIN_FREE_TMP_MB )); then
        log_error "Insufficient tmpfs space (${free_mb:-?}MB free, need ${BACKUP_MIN_FREE_TMP_MB}MB)"
        return 1
    fi

    export PG_STDERR_FILE="${tmp}/psql.stderr"

    # Leader re-check immediately before dumping (switchover guard).
    if ! leader_gate; then
        log_warn "Leadership lost before dump; aborting run"
        return 1
    fi

    local pg_version
    pg_version=$(pg_server_version) || pg_version=""
    if [[ -z "$pg_version" ]]; then
        log_error "Cannot determine server version (psql stderr: $(stderr_summarize "$PG_STDERR_FILE"))"
        return 1
    fi

    local databases
    databases=$(pg_list_databases)
    if [[ -z "$databases" ]]; then
        log_error "No databases enumerated"
        return 1
    fi
    log_info "Databases: $(echo "$databases" | tr '\n' ' ')"

    local databases_json="[]" all_snapshot_consistent=true
    local db object snapshot collect_json entry_json
    local sizes_tmp="${tmp}/dump_sizes"
    : > "$sizes_tmp"

    export PG_SESSION_TMPDIR="$tmp"
    for db in $databases; do
        object="${db}.dump.enc"
        snapshot=""
        collect_json=""

        pg_session_open "$db" "${tmp}/session.stderr"
        if pg_snapshot_begin; then
            snapshot="$PG_SNAPSHOT_ID"
            log_info "Snapshot exported for ${db}"
            if pg_collect_validation "$db" session true; then
                collect_json="$PG_COLLECT_JSON"
            else
                log_warn "In-snapshot validation counts failed for ${db}; falling back"
                snapshot=""
            fi
        else
            log_warn "Snapshot export failed for ${db} (stderr: $(stderr_summarize "${tmp}/session.stderr")); falling back to post-dump counts"
            snapshot=""
        fi

        if ! pipeline_dump_database "$db" "backups/${backup_id}/${object}" "$tmp" "$deadline" "$snapshot"; then
            pg_session_close
            log_error "Dump failed for ${db}"
            return 1
        fi
        pg_session_close

        if [[ -z "$collect_json" ]]; then
            all_snapshot_consistent=false
            if pg_collect_validation "$db" direct false; then
                collect_json="$PG_COLLECT_JSON"
            else
                log_error "Post-dump validation counts failed for ${db}"
                return 1
            fi
        fi

        entry_json=$(manifest_db_entry "$db" "$object" "$(pg_database_size "$db")" \
            "$PIPE_PLAIN_SIZE" "$PIPE_CIPHER_SIZE" "$PIPE_PLAIN_SHA" "$PIPE_CIPHER_SHA" \
            "$collect_json") || return 1
        databases_json=$(jq --argjson e "$entry_json" '. + [$e]' <<<"$databases_json") || return 1
        echo "$db $PIPE_PLAIN_SIZE" >> "$sizes_tmp"
        log_info "Dumped ${db}: ${PIPE_PLAIN_SIZE} bytes plaintext, ${PIPE_CIPHER_SIZE} bytes ciphertext"
    done

    if ! pipeline_dump_globals "backups/${backup_id}/globals.sql.gz.enc" "$tmp" "$deadline"; then
        log_error "Globals dump failed"
        return 1
    fi
    local globals_json
    globals_json=$(manifest_globals_entry "$PIPE_PLAIN_SHA" "$PIPE_CIPHER_SHA" \
        "$PIPE_PLAIN_SIZE" "$PIPE_CIPHER_SIZE")
    echo "_globals $PIPE_PLAIN_SIZE" >> "$sizes_tmp"

    # Manifest last: presence == complete.
    local completed_at duration manifest
    completed_at=$(date -u +%FT%TZ)
    duration=$(( $(date +%s) - start_epoch ))
    manifest=$(manifest_build "$backup_id" "$(cycle_key_for "$start_epoch")" "$trigger" \
        "${BACKUP_CLUSTER_NAME}-${BACKUP_ENV_NAME}" "$BACKUP_ENV_NAME" \
        "$started_at" "$completed_at" "$duration" "$MEMBER_HOST" "$pg_version" \
        "$all_snapshot_consistent" "$globals_json" "$databases_json" \
        "$BACKUP_KEY_PATH" "$BACKUP_RETENTION_DAYS") || return 1

    local attempt uploaded=0
    for attempt in 1 2 3; do
        if echo "$manifest" | s3_put_stream "backups/${backup_id}/manifest.json"; then
            uploaded=1
            break
        fi
        log_warn "Manifest upload failed (attempt ${attempt}/3)"
        sleep $(( attempt * 5 ))
    done
    if [[ "$uploaded" -ne 1 ]]; then
        log_error "Manifest upload failed; backup ${backup_id} is incomplete"
        return 1
    fi

    # Pointer update. Manual runs carry the previous scheduled cycle forward.
    local last_cycle
    if [[ "$trigger" == "scheduled" ]]; then
        last_cycle=$(cycle_key_for "$start_epoch")
    else
        last_cycle=$(latest_fetch | jq -r '.last_scheduled_cycle // empty' 2>/dev/null) || last_cycle=""
    fi
    latest_update "$(latest_build "$backup_id" "backups/${backup_id}/manifest.json" \
        "$completed_at" "$trigger" "$last_cycle")" || true

    cp "$sizes_tmp" "$M_DUMP_SIZES_FILE" 2>/dev/null || true
    M_LAST_SUCCESS_TS=$(date +%s)
    M_LAST_RUN_DURATION="$duration"
    log_info "Backup ${backup_id} complete in ${duration}s"
    return 0
}

run_backup_with_retries() {
    local trigger="$1"
    local attempts=$(( 1 + BACKUP_RETRY_MAX ))
    local i rc

    for (( i = 1; i <= attempts; i++ )); do
        M_LAST_RUN_TS=$(date +%s)
        metrics_render
        rc=0
        run_backup_once "$trigger" || rc=$?
        if [[ "$rc" -eq 0 ]]; then
            M_LAST_RUN_SUCCESS=1
            M_RUNS_SUCCESS_TOTAL=$(( M_RUNS_SUCCESS_TOTAL + 1 ))
            LAST_FAILURE_EPOCH=0
            metrics_render
            return 0
        fi
        M_LAST_RUN_SUCCESS=0
        M_RUNS_FAILURE_TOTAL=$(( M_RUNS_FAILURE_TOTAL + 1 ))
        metrics_render
        if (( i < attempts )); then
            log_warn "Backup attempt ${i}/${attempts} failed; retrying in ${BACKUP_RETRY_DELAY_SECONDS}s"
            sleep "$BACKUP_RETRY_DELAY_SECONDS"
        fi
    done
    LAST_FAILURE_EPOCH=$(date +%s)
    log_error "Backup failed after ${attempts} attempts; next attempt after cooldown or by peer"
    return 1
}

# ---------------------------------------------------------------------------
# Tick evaluation: manual trigger > schedule/interval. Leader-gated, locked.
# ---------------------------------------------------------------------------

oldest_manual_marker() {
    s3_list_keys "control/triggers/" | grep -E '/manual-[^/]+\.json$' | head -n 1 || true
}

check_and_run() {
    local now
    now=$(date +%s)

    # Cooldown after an exhausted retry cycle so a persistent failure does
    # not hot-loop every tick (the peer, if leader, converges independently).
    if (( LAST_FAILURE_EPOCH > 0 && now - LAST_FAILURE_EPOCH < BACKUP_RETRY_DELAY_SECONDS )); then
        return 0
    fi

    local trigger="" marker=""
    marker=$(oldest_manual_marker)
    if [[ -n "$marker" ]]; then
        trigger="manual:$(basename "$marker" .json)"
    else
        local latest last_cycle last_completed=""
        latest=$(latest_fetch) || latest=""
        if [[ -n "${BACKUP_INTERVAL_SECONDS}" ]]; then
            local completed_at
            completed_at=$(jq -r '.completed_at // empty' <<<"$latest" 2>/dev/null) || completed_at=""
            [[ -n "$completed_at" ]] \
                && last_completed=$(date -u -d "$completed_at" +%s 2>/dev/null)
            [[ "$(interval_owed "$now" "$last_completed" "$BACKUP_INTERVAL_SECONDS")" == "yes" ]] \
                && trigger="scheduled"
        else
            last_cycle=$(jq -r '.last_scheduled_cycle // empty' <<<"$latest" 2>/dev/null) || last_cycle=""
            [[ "$(cycle_owed "$now" "$BACKUP_SCHEDULE_UTC" "$last_cycle")" == "yes" ]] \
                && trigger="scheduled"
        fi
    fi
    [[ -n "$trigger" ]] || return 0

    export PG_STDERR_FILE="/run/backup/gate.stderr"
    : > "$PG_STDERR_FILE"
    if ! leader_gate; then
        return 0
    fi

    # Jitter scheduled runs so both members racing the same cycle mostly
    # avoid lock contention. Manual triggers run promptly.
    if [[ "$trigger" == "scheduled" && "$BACKUP_JITTER_SECONDS" -gt 0 ]]; then
        local jitter=$(( RANDOM % BACKUP_JITTER_SECONDS ))
        log_info "Run owed (${trigger}); jitter sleep ${jitter}s"
        sleep "$jitter"
    fi

    acquire_lock || return 0
    lock_renewal_start

    local run_it=1
    # Re-check under the lock: the peer may have completed this cycle (or
    # claimed the marker) while we waited out jitter/lock.
    if [[ -n "$marker" ]]; then
        if ! s3_exists "$marker"; then
            log_info "Manual trigger ${marker} already claimed"
            run_it=0
        elif ! s3_delete "$marker"; then
            log_warn "Failed to claim manual trigger ${marker}"
            run_it=0
        else
            log_info "Claimed manual trigger ${marker}"
        fi
    elif [[ -z "${BACKUP_INTERVAL_SECONDS}" ]]; then
        local last_cycle
        last_cycle=$(latest_fetch | jq -r '.last_scheduled_cycle // empty' 2>/dev/null) || last_cycle=""
        if [[ "$(cycle_owed "$(date +%s)" "$BACKUP_SCHEDULE_UTC" "$last_cycle")" != "yes" ]]; then
            log_info "Cycle completed by peer while waiting; skipping"
            run_it=0
        fi
    fi

    if [[ "$run_it" -eq 1 ]]; then
        run_backup_with_retries "$trigger" || true
    fi

    lock_renewal_stop
    release_lock || true
    return 0
}

# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------

LAST_FAILURE_EPOCH=0

cleanup() {
    lock_renewal_stop
    if [[ "${LOCK_HELD:-0}" -eq 1 ]]; then
        release_lock || true
    fi
    metrics_server_stop
    pg_session_close
}

main_backup() {
    log_info "pg-backup starting (mode: backup)"
    validate_backup_env
    mkdir -p /run/backup
    metrics_init
    metrics_server_start
    trap cleanup EXIT TERM INT

    local now next_heartbeat=0
    while true; do
        now=$(date +%s)
        latest_repair_tick || true
        if (( now >= next_heartbeat )); then
            metrics_heartbeat || true
            next_heartbeat=$(( now + BACKUP_HEARTBEAT_SECONDS ))
        fi
        if [[ "$BACKUP_ENABLED" == "true" ]]; then
            check_and_run || true
        fi
        sleep "$BACKUP_TICK_SECONDS"
    done
}

main() {
    case "${PG_BACKUP_MODE:-backup}" in
        backup)
            main_backup
            ;;
        restore)
            source "$SCRIPT_DIR/lib/restore.sh"
            restore_main
            ;;
        *)
            log_error "Unknown PG_BACKUP_MODE '${PG_BACKUP_MODE}' (expected backup|restore)"
            exit 1
            ;;
    esac
}

# Allow sourcing for unit tests (bats) without starting the daemon.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
