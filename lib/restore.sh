#!/usr/bin/env bash
# Restore drill driver (PG_BACKUP_MODE=restore). Runs one-shot inside the
# ephemeral postgres-restore-test CVM next to a fresh postgres:16 instance:
#
#   download → ciphertext sha256 vs manifest → GetKey(manifest key_path) →
#   decrypt → plaintext sha256 vs manifest → PG major gate → globals via psql
#   (only "already exists" benign) → per-db pg_restore --create -j4 →
#   validation battery → sanitized report JSON → exit code by verdict.
#
# The report carries counts/IDs/checksums/durations only. Raw pg_restore /
# psql stderr never leaves the CVM (it dies with the instance); it is
# summarized as whitelisted error classes.

# Migration floors, as-of 2026-07. The manifest is the authority (equality
# is the check); floors only guard against restoring an implausibly old dump.
RESTORE_FLOOR_CLOUD_API_VERSION=63
RESTORE_FLOOR_CLOUD_API_ROWS=62
RESTORE_FLOOR_CHAT_API_VERSION=34
RESTORE_FLOOR_CHAT_API_ROWS=33

# Tables allowed count drift when the manifest counts are not
# snapshot-consistent (post-dump fallback): 2% relative + 100 rows absolute.
RESTORE_HIGH_CHURN_TABLES="organization_usage_log responses response_items user_usage_event sessions conversations"

RESTORE_CHECKS_FILE=""
RESTORE_PHASES_FILE=""
RESTORE_ERROR_CLASSES="{}"
RESTORE_SIZES="{}"
RESTORE_NOTES='["prod app-role password is underivable outside prod by design; connectivity verified via ALTER ROLE + fresh SCRAM login"]'
RESTORE_REPORT_UPLOADED=0
RESTORE_STARTED_AT=""
DRILL_PGPASSWORD=""

# ---------------------------------------------------------------------------
# Report plumbing
# ---------------------------------------------------------------------------

check_add() {
    local id="$1" expected="$2" observed="$3" pass="$4"
    jq -cn --arg id "$id" --arg expected "$expected" --arg observed "$observed" \
        --argjson pass "$pass" \
        '{id: $id, expected: $expected, observed: $observed, pass: $pass}' \
        >> "$RESTORE_CHECKS_FILE"
    if [[ "$pass" == "true" ]]; then
        log_info "check ${id}: PASS"
    else
        log_error "check ${id}: FAIL (expected: ${expected}; observed: ${observed})"
    fi
}

phase_record() {
    local name="$1" seconds="$2"
    echo "${name} ${seconds}" >> "$RESTORE_PHASES_FILE"
    progress_put "$name"
}

# Sanitized liveness marker for the workflow's await step: phase name and
# timestamp only, uploaded best-effort so a marker gap never fails a drill.
# Its absence is itself diagnostic (driver never started or has no egress).
progress_put() {
    local phase="$1"
    jq -n --arg d "${DRILL_ID:-unset}" --arg p "$phase" --arg t "$(date -u +%FT%TZ)"         '{drill_id: $d, phase: $p, at: $t}'         | aws s3 cp - "s3://${RESTORE_S3_BUCKET}/${RESTORE_REPORT_PREFIX}/${DRILL_ID}.progress.json"             >/dev/null 2>&1         || log_warn "progress marker upload failed (phase ${phase})"
}

error_class_add() {
    local scope="$1" summary="$2"
    RESTORE_ERROR_CLASSES=$(jq -c --arg s "$scope" --arg v "$summary" '. + {($s): $v}' \
        <<<"$RESTORE_ERROR_CLASSES")
}

size_add() {
    local name="$1" plain="$2" cipher="$3"
    RESTORE_SIZES=$(jq -c --arg n "$name" --argjson p "${plain:-0}" --argjson c "${cipher:-0}" \
        '. + {($n): {plaintext_bytes: $p, ciphertext_bytes: $c}}' <<<"$RESTORE_SIZES")
}

restore_report_write() {
    local verdict="$1"
    local completed_at rto_total phases_json
    completed_at=$(date -u +%FT%TZ)
    phases_json="{}"
    local name seconds
    while read -r name seconds; do
        [[ -n "$name" ]] || continue
        phases_json=$(jq -c --arg n "$name" --argjson s "$seconds" '. + {($n): $s}' <<<"$phases_json")
    done < "$RESTORE_PHASES_FILE"
    rto_total=$(( $(date +%s) - RESTORE_START_EPOCH ))

    local backup_id backup_started backup_completed manifest_sha
    backup_id=$(jq -r '.backup_id // "unknown"' "$RESTORE_WORK_DIR/manifest.json" 2>/dev/null) || backup_id="unknown"
    backup_started=$(jq -r '.started_at // empty' "$RESTORE_WORK_DIR/manifest.json" 2>/dev/null) || backup_started=""
    backup_completed=$(jq -r '.completed_at // empty' "$RESTORE_WORK_DIR/manifest.json" 2>/dev/null) || backup_completed=""
    manifest_sha=$(sha256sum "$RESTORE_WORK_DIR/manifest.json" 2>/dev/null | awk '{print $1}') || manifest_sha=""

    local backup_age="" data_age=""
    if [[ -n "$backup_started" ]]; then
        backup_age=$(( $(date +%s) - $(date -u -d "$backup_started" +%s 2>/dev/null || echo 0) ))
    fi
    [[ -n "${RESTORE_DATA_AGE_SECONDS:-}" ]] && data_age="$RESTORE_DATA_AGE_SECONDS"

    jq -n \
        --arg drill_id "$DRILL_ID" \
        --arg started_at "$RESTORE_STARTED_AT" \
        --arg completed_at "$completed_at" \
        --arg backup_id "$backup_id" \
        --arg manifest_key "$RESTORE_MANIFEST_KEY" \
        --arg manifest_sha256 "$manifest_sha" \
        --arg backup_started_at "$backup_started" \
        --arg backup_completed_at "$backup_completed" \
        --argjson backup_age "${backup_age:-null}" \
        --argjson data_age "${data_age:-null}" \
        --argjson rpo_target "$RESTORE_RPO_TARGET_SECONDS" \
        --argjson phases "$phases_json" \
        --argjson rto_total "$rto_total" \
        --argjson rto_target "$RESTORE_RTO_TARGET_SECONDS" \
        --slurpfile checks_raw "$RESTORE_CHECKS_FILE" \
        --argjson error_classes "$RESTORE_ERROR_CLASSES" \
        --argjson sizes "$RESTORE_SIZES" \
        --argjson notes "$RESTORE_NOTES" \
        --arg verdict "$verdict" \
        '{format_version: 1,
          drill_id: $drill_id,
          started_at: $started_at, completed_at: $completed_at,
          backup: {backup_id: $backup_id, manifest_key: $manifest_key,
                   manifest_sha256: $manifest_sha256,
                   started_at: $backup_started_at, completed_at: $backup_completed_at},
          rpo: {backup_age_seconds: $backup_age, data_age_seconds: $data_age,
                target_seconds: $rpo_target},
          rto: {phases: $phases, total_seconds: $rto_total, target_seconds: $rto_target},
          checks: $checks_raw,
          error_classes: $error_classes,
          sizes: $sizes,
          notes: $notes,
          verdict: $verdict}' \
        > "$RESTORE_WORK_DIR/report.json"
}

restore_report_upload() {
    local attempt
    for attempt in 1 2 3; do
        if s3_put_file "$RESTORE_WORK_DIR/report.json" \
            "${RESTORE_REPORT_PREFIX}/${DRILL_ID}.json"; then
            RESTORE_REPORT_UPLOADED=1
            log_info "Report uploaded to ${RESTORE_REPORT_PREFIX}/${DRILL_ID}.json"
            return 0
        fi
        log_warn "Report upload failed (attempt ${attempt}/3)"
        sleep $(( attempt * 5 ))
    done
    return 1
}

restore_verdict() {
    if jq -es 'length > 0 and all(.pass)' "$RESTORE_CHECKS_FILE" >/dev/null 2>&1; then
        echo "PASS"
    else
        echo "FAIL"
    fi
}

restore_on_exit() {
    local rc=$?
    if [[ "$RESTORE_REPORT_UPLOADED" -eq 0 && -n "$RESTORE_CHECKS_FILE" ]]; then
        # Unexpected exit: publish a FAIL report with whatever checks ran.
        RESTORE_NOTES=$(jq -c '. + ["driver exited unexpectedly before completing the battery"]' <<<"$RESTORE_NOTES")
        restore_report_write "FAIL" || true
        restore_report_upload || true
    fi
    exit "$rc"
}

# ---------------------------------------------------------------------------
# Drill-instance psql helpers
# ---------------------------------------------------------------------------

# Query the drill instance. Rows on stdout; stderr to $2 (default discard
# into the phase stderr file). Never leaks values: callers only use counts.
rq() {
    local db="$1" sql="$2"
    PGPASSWORD="$DRILL_PGPASSWORD" PGAPPNAME="nearai-restore-drill" \
        psql -X -q -A -t --no-password \
        -h "$RESTORE_PG_HOST" -p "$RESTORE_PG_PORT" -U postgres -d "$db" \
        -c "$sql" 2>>"$RESTORE_STDERR_DIR/validate.stderr"
}

db_prefix() {
    case "$1" in
        postgres) echo "cloud_api" ;;
        chat_api) echo "chat_api" ;;
        *) echo "$1" ;;
    esac
}

valid_identifier() {
    [[ "$1" =~ ^[a-z_][a-z0-9_]*$ ]]
}

# ---------------------------------------------------------------------------
# Spilo-artifact tolerance
#
# Production dumps come from Spilo-16 clusters; the drill restores onto a
# vanilla postgres:16 instance. Spilo bakes in extensions and housekeeping
# schemas that vanilla does not ship, so pg_restore predictably fails on
# those objects HERE while a real DR restore (onto Spilo, where they exist)
# would not. Missing-object errors whose identifier matches this whitelist
# are TOLERATED: counted separately and excluded from the pass/fail
# decision. Everything else still fails the check. Only these whitelisted
# identifiers (infra metadata, never row data) may appear in the report.
# ---------------------------------------------------------------------------
SPILO_ARTIFACT_EXTENSIONS=(bg_mon pg_auth_mon pg_cron pg_stat_kcache set_user
    pg_permissions file_fdw pg_stat_statements)
SPILO_ARTIFACT_SCHEMAS=(metric_helpers user_management robot_zmon zalando admin)

# spilo_artifact_tolerated <kind> <identifier> → 0 if whitelisted.
#   extension        — exact match against SPILO_ARTIFACT_EXTENSIONS
#   schema, role     — exact match against SPILO_ARTIFACT_SCHEMAS (Spilo's
#                      admin/robot_zmon/zalando exist as roles too)
#   function, relation — qualified name inside a whitelisted schema
spilo_artifact_tolerated() {
    local kind="$1" name="$2" w
    case "$kind" in
        extension)
            for w in "${SPILO_ARTIFACT_EXTENSIONS[@]}"; do
                [[ "$name" == "$w" ]] && return 0
            done
            ;;
        schema | role)
            for w in "${SPILO_ARTIFACT_SCHEMAS[@]}"; do
                [[ "$name" == "$w" ]] && return 0
            done
            ;;
        function | relation)
            for w in "${SPILO_ARTIFACT_SCHEMAS[@]}"; do
                [[ "$name" == "$w".* ]] && return 0
            done
            ;;
    esac
    return 1
}

# Classify the error lines of a captured pg_restore/psql stderr file into
# tolerated (whitelisted Spilo missing objects) vs blocking. Only actual
# error lines ('pg_restore: error:' anywhere, or a line starting 'ERROR:')
# are counted — cascading DETAIL/HINT/LINE context lines are not errors.
# The file stays in the CVM; raw lines are NEVER emitted. Results:
#   RESTORE_ERR_TOTAL / RESTORE_ERR_TOLERATED / RESTORE_ERR_BLOCKING
#   RESTORE_ERR_TOLERATED_IDS — deduped "kind identifier" entries, one per
#   line, whitelist-matched only (safe for the report).
restore_classify_errors() {
    local file="$1"
    RESTORE_ERR_TOTAL=0
    RESTORE_ERR_TOLERATED=0
    RESTORE_ERR_BLOCKING=0
    RESTORE_ERR_TOLERATED_IDS=""
    [[ -s "$file" ]] || return 0

    # "is not available" is what CREATE EXTENSION emits when the extension
    # files are absent from the server (the vanilla-image case); COMMENT ON /
    # DROP emit "does not exist" for the same root cause.
    local re_ext='extension "([A-Za-z0-9_-]+)" (does not exist|is not available)'
    local re_schema='schema "([A-Za-z0-9_-]+)" does not exist'
    local re_func='function ([A-Za-z0-9_."]+)\([^)]*\) does not exist'
    local re_rel='relation "([A-Za-z0-9_."-]+)" does not exist'
    local re_role='role "([A-Za-z0-9_-]+)" does not exist'

    local line kind name entry
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" == *"pg_restore: error:"* || "$line" =~ ^ERROR: ]] || continue
        RESTORE_ERR_TOTAL=$(( RESTORE_ERR_TOTAL + 1 ))
        kind="" name=""
        if [[ "$line" =~ $re_ext ]]; then
            kind=extension name="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ $re_schema ]]; then
            kind=schema name="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ $re_func ]]; then
            kind=function name="${BASH_REMATCH[1]//\"/}"
        elif [[ "$line" =~ $re_rel ]]; then
            kind=relation name="${BASH_REMATCH[1]//\"/}"
        elif [[ "$line" =~ $re_role ]]; then
            kind=role name="${BASH_REMATCH[1]}"
        fi
        if [[ -n "$kind" ]] && spilo_artifact_tolerated "$kind" "$name"; then
            RESTORE_ERR_TOLERATED=$(( RESTORE_ERR_TOLERATED + 1 ))
            entry="${kind} ${name}"
            if [[ $'\n'"${RESTORE_ERR_TOLERATED_IDS}"$'\n' != *$'\n'"${entry}"$'\n'* ]]; then
                if [[ -n "$RESTORE_ERR_TOLERATED_IDS" ]]; then
                    RESTORE_ERR_TOLERATED_IDS+=$'\n'"$entry"
                else
                    RESTORE_ERR_TOLERATED_IDS="$entry"
                fi
            fi
        else
            RESTORE_ERR_BLOCKING=$(( RESTORE_ERR_BLOCKING + 1 ))
        fi
    done < "$file"
    return 0
}

# Render RESTORE_ERR_TOLERATED_IDS as "extension bg_mon, schema
# metric_helpers, ..." capped at 10 identifiers ("+N more" beyond that).
restore_tolerated_summary() {
    local cap=10 shown=0 total=0 out="" entry
    while IFS= read -r entry; do
        [[ -n "$entry" ]] || continue
        total=$(( total + 1 ))
        if (( shown < cap )); then
            out+="${out:+, }${entry}"
            shown=$(( shown + 1 ))
        fi
    done <<<"$RESTORE_ERR_TOLERATED_IDS"
    if (( total > shown )); then
        out+=" +$(( total - shown )) more"
    fi
    echo "$out"
}

# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------

restore_validate_env() {
    local missing=0 var
    for var in RESTORE_MANIFEST_KEY RESTORE_S3_BUCKET RESTORE_AWS_ACCESS_KEY_ID \
        RESTORE_AWS_SECRET_ACCESS_KEY RESTORE_PG_PASSWORD DRILL_ID; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Required environment variable $var is not set"
            missing=1
        fi
    done
    [[ "$missing" -eq 0 ]] || exit 1

    export RESTORE_AWS_REGION="${RESTORE_AWS_REGION:-us-west-2}"
    export RESTORE_REPORT_PREFIX="${RESTORE_REPORT_PREFIX:-restore-reports}"
    export RESTORE_PG_HOST="${RESTORE_PG_HOST:-postgres}"
    export RESTORE_PG_PORT="${RESTORE_PG_PORT:-5432}"
    export RESTORE_WORK_DIR="${RESTORE_WORK_DIR:-/work}"
    export RESTORE_BUCKET_CHECK="${RESTORE_BUCKET_CHECK:-true}"
    export RESTORE_RTO_TARGET_SECONDS="${RESTORE_RTO_TARGET_SECONDS:-14400}"
    export RESTORE_RPO_TARGET_SECONDS="${RESTORE_RPO_TARGET_SECONDS:-86400}"
    export BACKUP_KEY_SOURCE="${BACKUP_KEY_SOURCE:-dstack}"

    export AWS_ACCESS_KEY_ID="$RESTORE_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$RESTORE_AWS_SECRET_ACCESS_KEY"
    export AWS_DEFAULT_REGION="$RESTORE_AWS_REGION"
    export S3_BUCKET="$RESTORE_S3_BUCKET"
}

restore_download() {
    local t0=$SECONDS
    s3_get_file "$RESTORE_MANIFEST_KEY" "$RESTORE_WORK_DIR/manifest.json" || {
        log_error "Failed to download manifest ${RESTORE_MANIFEST_KEY}"
        check_add "cluster.manifest_complete" "manifest downloadable and parsable" "download failed" false
        return 1
    }
    if ! jq -e '.format_version and .backup_id and .databases and .globals and .encryption.key_path' \
        "$RESTORE_WORK_DIR/manifest.json" >/dev/null 2>&1; then
        check_add "cluster.manifest_complete" "manifest downloadable and parsable" "unparsable manifest" false
        return 1
    fi

    RESTORE_BACKUP_PREFIX=$(dirname "$RESTORE_MANIFEST_KEY")
    mapfile -t RESTORE_DBS < <(jq -r '.databases[].name' "$RESTORE_WORK_DIR/manifest.json")

    local obj db
    obj=$(jq -r '.globals.object' "$RESTORE_WORK_DIR/manifest.json")
    s3_get_file "${RESTORE_BACKUP_PREFIX}/${obj}" "$RESTORE_WORK_DIR/enc/${obj}" || {
        check_add "cluster.manifest_complete" "all objects downloadable" "globals object missing" false
        return 1
    }
    for db in "${RESTORE_DBS[@]}"; do
        obj=$(jq -r --arg db "$db" '.databases[] | select(.name == $db) | .object' \
            "$RESTORE_WORK_DIR/manifest.json")
        s3_get_file "${RESTORE_BACKUP_PREFIX}/${obj}" "$RESTORE_WORK_DIR/enc/${obj}" || {
            check_add "cluster.manifest_complete" "all objects downloadable" "object for ${db} missing" false
            return 1
        }
    done
    check_add "cluster.manifest_complete" "manifest + $(( ${#RESTORE_DBS[@]} + 1 )) objects downloaded" \
        "all present" true
    phase_record download $(( SECONDS - t0 ))
}

restore_verify_ciphertext() {
    local t0=$SECONDS total=0 bad=""
    local obj want got
    while IFS=$'\t' read -r obj want; do
        total=$(( total + 1 ))
        got=$(sha256sum "$RESTORE_WORK_DIR/enc/${obj}" | awk '{print $1}')
        [[ "$got" == "$want" ]] || bad="${bad} ${obj}"
    done < <(jq -r '([.globals] + .databases)[] | [.object, .sha256_ciphertext] | @tsv' \
        "$RESTORE_WORK_DIR/manifest.json")

    if [[ -z "$bad" ]]; then
        check_add "cluster.ciphertext_sha256" "${total}/${total} objects match manifest" \
            "${total}/${total} match" true
    else
        check_add "cluster.ciphertext_sha256" "${total}/${total} objects match manifest" \
            "mismatch:${bad}" false
        return 1
    fi
    phase_record verify_ciphertext $(( SECONDS - t0 ))
}

restore_decrypt() {
    local t0=$SECONDS total=0 bad=""
    local key_path
    key_path=$(jq -r '.encryption.key_path' "$RESTORE_WORK_DIR/manifest.json")
    fetch_encryption_key "$key_path" || {
        check_add "cluster.plaintext_sha256" "objects decrypt and match manifest" \
            "encryption key unavailable (path: ${key_path})" false
        return 1
    }

    local obj want got plain
    while IFS=$'\t' read -r obj want; do
        total=$(( total + 1 ))
        plain="$RESTORE_WORK_DIR/plain/${obj%.enc}"
        if ! openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_ENCRYPTION_KEY \
            -in "$RESTORE_WORK_DIR/enc/${obj}" -out "$plain" \
            2>"$RESTORE_STDERR_DIR/decrypt.stderr"; then
            bad="${bad} ${obj}(decrypt:$(stderr_summarize "$RESTORE_STDERR_DIR/decrypt.stderr"))"
            continue
        fi
        got=$(sha256sum "$plain" | awk '{print $1}')
        [[ "$got" == "$want" ]] || bad="${bad} ${obj}(sha256)"
        size_add "${obj%.enc}" "$(wc -c <"$plain")" "$(wc -c <"$RESTORE_WORK_DIR/enc/${obj}")"
    done < <(jq -r '([.globals] + .databases)[] | [.object, .sha256_plaintext] | @tsv' \
        "$RESTORE_WORK_DIR/manifest.json")

    if [[ -z "$bad" ]]; then
        check_add "cluster.plaintext_sha256" "${total}/${total} objects decrypt and match manifest" \
            "${total}/${total} match" true
    else
        check_add "cluster.plaintext_sha256" "${total}/${total} objects decrypt and match manifest" \
            "failed:${bad}" false
        return 1
    fi
    # Ciphertext no longer needed; free the disk before pg_restore.
    rm -rf "$RESTORE_WORK_DIR/enc"
    phase_record decrypt $(( SECONDS - t0 ))
}

restore_wait_pg() {
    local attempts=0
    until pg_isready -h "$RESTORE_PG_HOST" -p "$RESTORE_PG_PORT" -U postgres -q; do
        attempts=$(( attempts + 1 ))
        if (( attempts >= 150 )); then
            log_error "Timed out waiting for the drill postgres instance"
            return 1
        fi
        sleep 2
    done
}

restore_pg_major_gate() {
    local expected observed
    expected=$(jq -r '.source.pg_version' "$RESTORE_WORK_DIR/manifest.json" | cut -d. -f1)
    observed=$(rq postgres "SHOW server_version" | cut -d. -f1)
    if [[ "$observed" == "$expected" ]]; then
        check_add "cluster.pg_major" "server major == ${expected}" "$observed" true
    else
        check_add "cluster.pg_major" "server major == ${expected}" "${observed:-unknown}" false
        return 1
    fi
}

restore_globals() {
    local t0=$SECONDS
    gunzip -c "$RESTORE_WORK_DIR/plain/globals.sql.gz" > "$RESTORE_WORK_DIR/plain/globals.sql" || {
        check_add "cluster.globals_errors" "globals decompress + apply" "gunzip failed" false
        return 1
    }

    # Apply globals and reset the postgres password in the SAME session: the
    # dump overwrites the postgres role with the prod SCRAM hash (underivable
    # here), so a follow-up connection would be locked out otherwise.
    DRILL_PGPASSWORD=$(openssl rand -hex 24)
    {
        cat "$RESTORE_WORK_DIR/plain/globals.sql"
        printf "ALTER ROLE postgres PASSWORD '%s';\n" "$DRILL_PGPASSWORD"
    } | PGPASSWORD="$RESTORE_PG_PASSWORD" psql -X -q --no-password \
        -h "$RESTORE_PG_HOST" -p "$RESTORE_PG_PORT" -U postgres -d postgres \
        -v ON_ERROR_STOP=off -f - \
        >/dev/null 2>"$RESTORE_STDERR_DIR/globals.stderr" || true

    local errors summary
    errors=$(stderr_count_errors "$RESTORE_STDERR_DIR/globals.stderr" "already exists")
    summary=$(stderr_summarize "$RESTORE_STDERR_DIR/globals.stderr")
    error_class_add "globals" "$summary"
    if [[ "$errors" -eq 0 ]]; then
        check_add "cluster.globals_errors" "0 non-benign errors (only 'already exists' benign)" \
            "0 (stderr: ${summary})" true
    else
        check_add "cluster.globals_errors" "0 non-benign errors (only 'already exists' benign)" \
            "${errors} (stderr: ${summary})" false
    fi

    # Fresh SCRAM TCP login with the drill password must now work.
    local probe
    probe=$(rq postgres "SELECT 1") || probe=""
    if [[ "$probe" == "1" ]]; then
        check_add "cluster.app_role_connectivity" \
            "fresh SCRAM TCP login as postgres after ALTER ROLE" "login ok" true
    else
        check_add "cluster.app_role_connectivity" \
            "fresh SCRAM TCP login as postgres after ALTER ROLE" "login failed" false
        return 1
    fi
    phase_record globals $(( SECONDS - t0 ))
}

restore_databases() {
    local t0=$SECONDS db prefix dumpfile summary rc tol_note
    for db in "${RESTORE_DBS[@]}"; do
        prefix=$(db_prefix "$db")
        dumpfile="$RESTORE_WORK_DIR/plain/${db}.dump"
        log_info "Restoring ${db}..."

        # Uniform drop-first (idempotent for reruns; the maintenance DB is
        # template1 so the 'postgres' database itself can be recreated).
        rq template1 "DROP DATABASE IF EXISTS \"${db}\" WITH (FORCE)" >/dev/null || {
            check_add "${prefix}.restore_errors" "database droppable before restore" "drop failed" false
            continue
        }

        rc=0
        PGPASSWORD="$DRILL_PGPASSWORD" PGAPPNAME="nearai-restore-drill" \
            pg_restore --create -j 4 --no-password \
            -h "$RESTORE_PG_HOST" -p "$RESTORE_PG_PORT" -U postgres -d template1 \
            "$dumpfile" 2>"$RESTORE_STDERR_DIR/restore-${db}.stderr" || rc=$?

        # No --exit-on-error: collect the full error inventory, then assert
        # no BLOCKING errors remain (counts only — stderr can embed row
        # values). Whitelisted Spilo missing-object errors are tolerated:
        # they are drill-only (vanilla postgres:16 target) and would not
        # occur in real DR onto Spilo. pg_restore exits 1 whenever any error
        # was ignored, so rc=1 is acceptable iff every error was tolerated.
        restore_classify_errors "$RESTORE_STDERR_DIR/restore-${db}.stderr"
        summary=$(stderr_summarize "$RESTORE_STDERR_DIR/restore-${db}.stderr")
        error_class_add "$db" "$summary"
        tol_note=""
        if (( RESTORE_ERR_TOLERATED > 0 )); then
            tol_note=" (${RESTORE_ERR_TOLERATED} tolerated Spilo artifacts: $(restore_tolerated_summary))"
        fi
        if (( RESTORE_ERR_BLOCKING == 0 )) \
            && { [[ "$rc" -eq 0 ]] || { [[ "$rc" -eq 1 ]] && (( RESTORE_ERR_TOLERATED > 0 )); }; }; then
            check_add "${prefix}.restore_errors" "0 blocking pg_restore errors" \
                "0 blocking errors${tol_note} (stderr: ${summary})" true
        else
            check_add "${prefix}.restore_errors" "0 blocking pg_restore errors" \
                "${RESTORE_ERR_BLOCKING} blocking of ${RESTORE_ERR_TOTAL} errors, rc=${rc}${tol_note} (stderr: ${summary})" false
        fi
        rm -f "$dumpfile"
    done
    phase_record restore $(( SECONDS - t0 ))

    # Refresh planner stats (also populates reltuples for the sequence check).
    PGPASSWORD="$DRILL_PGPASSWORD" vacuumdb -h "$RESTORE_PG_HOST" -p "$RESTORE_PG_PORT" \
        -U postgres --all --analyze-only -j 4 \
        >/dev/null 2>>"$RESTORE_STDERR_DIR/validate.stderr" \
        || log_warn "vacuumdb --analyze-only failed (non-fatal)"
}

# ---------------------------------------------------------------------------
# Validation battery
# ---------------------------------------------------------------------------

validate_cluster() {
    # Databases match the manifest list.
    local observed missing="" db
    observed=$(rq postgres "SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname" | tr '\n' ' ')
    for db in "${RESTORE_DBS[@]}"; do
        [[ " $observed " == *" $db "* ]] || missing="${missing} ${db}"
    done
    if [[ -z "$missing" ]]; then
        check_add "cluster.databases_match" "all manifest databases present" "present: ${observed}" true
    else
        check_add "cluster.databases_match" "all manifest databases present" "missing:${missing}" false
    fi

    # Required roles present and login-capable.
    local roles
    roles=$(rq postgres "SELECT COUNT(*) FROM pg_roles WHERE rolname IN ('postgres','datadog') AND rolcanlogin")
    if [[ "$roles" == "2" ]]; then
        check_add "cluster.roles" "postgres + datadog present and login-capable" "2/2" true
    else
        check_add "cluster.roles" "postgres + datadog present and login-capable" "${roles:-0}/2" false
    fi
}

validate_database() {
    local db="$1"
    local prefix mig snapshot_consistent
    prefix=$(db_prefix "$db")
    mig=$(jq -c --arg db "$db" '.databases[] | select(.name == $db) | .migrations' \
        "$RESTORE_WORK_DIR/manifest.json")
    snapshot_consistent=$(jq -r --arg db "$db" \
        '.databases[] | select(.name == $db) | .validation.snapshot_consistent' \
        "$RESTORE_WORK_DIR/manifest.json")

    # Migrations (skip when the manifest recorded none, e.g. rag_service).
    if [[ "$mig" != "null" ]]; then
        local want_ver want_rows got_ver got_rows floor_ver=0 floor_rows=0
        want_ver=$(jq -r '.max_version' <<<"$mig")
        want_rows=$(jq -r '.row_count' <<<"$mig")
        case "$prefix" in
            cloud_api) floor_ver=$RESTORE_FLOOR_CLOUD_API_VERSION; floor_rows=$RESTORE_FLOOR_CLOUD_API_ROWS ;;
            chat_api) floor_ver=$RESTORE_FLOOR_CHAT_API_VERSION; floor_rows=$RESTORE_FLOOR_CHAT_API_ROWS ;;
        esac
        got_ver=$(rq "$db" "SELECT COALESCE(MAX(version), 0) FROM public.refinery_schema_history")
        got_rows=$(rq "$db" "SELECT COUNT(*) FROM public.refinery_schema_history")
        if [[ "$got_ver" == "$want_ver" ]] && (( got_ver >= floor_ver )); then
            check_add "${prefix}.migration_version" "MAX(version) == ${want_ver} (floor ${floor_ver})" "$got_ver" true
        else
            check_add "${prefix}.migration_version" "MAX(version) == ${want_ver} (floor ${floor_ver})" "${got_ver:-none}" false
        fi
        if [[ "$got_rows" == "$want_rows" ]] && (( got_rows >= floor_rows )); then
            check_add "${prefix}.migration_row_count" "COUNT(*) == ${want_rows} (floor ${floor_rows})" "$got_rows" true
        else
            check_add "${prefix}.migration_row_count" "COUNT(*) == ${want_rows} (floor ${floor_rows})" "${got_rows:-none}" false
        fi

        # Ownership spot-check: pg_restore ran without --no-owner, so the
        # migrations table must carry its original owner (postgres).
        local owner
        owner=$(rq "$db" "SELECT tableowner FROM pg_tables WHERE schemaname='public' AND tablename='refinery_schema_history'")
        if [[ "$owner" == "postgres" ]]; then
            check_add "${prefix}.ownership" "refinery_schema_history owned by postgres" "$owner" true
        else
            check_add "${prefix}.ownership" "refinery_schema_history owned by postgres" "${owner:-missing}" false
        fi
    fi

    # uuid-ossp (cloud-api + chat-api databases).
    if [[ "$db" == "postgres" || "$db" == "chat_api" ]]; then
        local ext
        ext=$(rq "$db" "SELECT COUNT(*) FROM pg_extension WHERE extname='uuid-ossp'")
        if [[ "$ext" == "1" ]]; then
            check_add "${prefix}.uuid_ossp" "extension present" "present" true
        else
            check_add "${prefix}.uuid_ossp" "extension present" "absent" false
        fi
    fi

    # Rename sentinels / dropped-table sentinel.
    if [[ "$db" == "postgres" ]]; then
        local s1 s2
        s1=$(rq "$db" "SELECT to_regclass('public.refresh_tokens') IS NOT NULL")
        s2=$(rq "$db" "SELECT to_regclass('public.model_history') IS NOT NULL")
        if [[ "$s1" == "t" && "$s2" == "t" ]]; then
            check_add "cloud_api.rename_sentinels" "refresh_tokens + model_history exist" "both exist" true
        else
            check_add "cloud_api.rename_sentinels" "refresh_tokens + model_history exist" \
                "refresh_tokens:${s1} model_history:${s2}" false
        fi
    fi
    if [[ "$db" == "chat_api" ]]; then
        local gone
        gone=$(rq "$db" "SELECT to_regclass('public.response_authors') IS NULL")
        if [[ "$gone" == "t" ]]; then
            check_add "chat_api.response_authors_absent" "table absent" "absent" true
        else
            check_add "chat_api.response_authors_absent" "table absent" "present" false
        fi
    fi

    # Representative-table counts + MAX(created_at) vs manifest.
    local tables_total=0 count_bad="" ts_bad="" newest_created=""
    local t want_count want_ts got is_churn tolerance lo hi
    while IFS=$'\t' read -r t want_count want_ts; do
        valid_identifier "$t" || continue
        tables_total=$(( tables_total + 1 ))
        got=$(rq "$db" "SELECT COUNT(*) FROM public.\"${t}\"")
        if [[ "$snapshot_consistent" == "true" ]]; then
            [[ "$got" == "$want_count" ]] || count_bad="${count_bad} ${t}"
        else
            is_churn=0
            [[ " $RESTORE_HIGH_CHURN_TABLES " == *" $t "* ]] && is_churn=1
            if [[ "$is_churn" -eq 1 ]]; then
                tolerance=$(( want_count / 50 + 100 ))
                lo=$(( want_count - tolerance )); hi=$(( want_count + tolerance ))
                { [[ "$got" =~ ^[0-9]+$ ]] && (( got >= lo && got <= hi )); } || count_bad="${count_bad} ${t}"
            else
                [[ "$got" == "$want_count" ]] || count_bad="${count_bad} ${t}"
            fi
        fi
        if [[ -n "$want_ts" && "$want_ts" != "null" ]]; then
            if [[ "$snapshot_consistent" == "true" ]]; then
                got=$(rq "$db" "SELECT MAX(created_at) = '${want_ts}'::timestamptz FROM public.\"${t}\"")
            else
                got=$(rq "$db" "SELECT MAX(created_at) >= '${want_ts}'::timestamptz FROM public.\"${t}\"")
            fi
            [[ "$got" == "t" ]] || ts_bad="${ts_bad} ${t}"
            if [[ -z "$newest_created" || "$want_ts" > "$newest_created" ]]; then
                newest_created="$want_ts"
            fi
        fi
    done < <(jq -r --arg db "$db" \
        '.databases[] | select(.name == $db) | .validation.tables | to_entries[] | [.key, (.value.count | tostring), (.value.max_created_at // "null")] | @tsv' \
        "$RESTORE_WORK_DIR/manifest.json")

    if (( tables_total > 0 )); then
        if [[ -z "$count_bad" ]]; then
            check_add "${prefix}.table_counts" \
                "${tables_total}/${tables_total} tables match manifest (snapshot_consistent=${snapshot_consistent})" \
                "all match" true
        else
            check_add "${prefix}.table_counts" \
                "${tables_total}/${tables_total} tables match manifest (snapshot_consistent=${snapshot_consistent})" \
                "mismatch:${count_bad}" false
        fi
        if [[ -z "$ts_bad" ]]; then
            check_add "${prefix}.max_created_at" "MAX(created_at) matches manifest per table" "all match" true
        else
            check_add "${prefix}.max_created_at" "MAX(created_at) matches manifest per table" "mismatch:${ts_bad}" false
        fi
    fi
    # Track the globally newest row timestamp for the RPO check.
    if [[ -n "$newest_created" ]]; then
        if [[ -z "${RESTORE_NEWEST_CREATED_AT:-}" || "$newest_created" > "$RESTORE_NEWEST_CREATED_AT" ]]; then
            RESTORE_NEWEST_CREATED_AT="$newest_created"
        fi
    fi

    # Index / FK / trigger counts vs manifest.
    local want got_n name query
    for name in index_count fk_count trigger_count; do
        want=$(jq -r --arg db "$db" --arg k "$name" \
            '.databases[] | select(.name == $db) | .validation[$k]' "$RESTORE_WORK_DIR/manifest.json")
        # Shared public-schema-scoped SQL from lib/pg.sh — the manifest side
        # runs the exact same statements, so both sides compare like for like.
        case "$name" in
            index_count) query="$PG_SQL_INDEX_COUNT" ;;
            fk_count) query="$PG_SQL_FK_COUNT" ;;
            trigger_count) query="$PG_SQL_TRIGGER_COUNT" ;;
        esac
        got_n=$(rq "$db" "$query")
        if [[ "$got_n" == "$want" ]]; then
            check_add "${prefix}.${name}" "== ${want}" "$got_n" true
        else
            check_add "${prefix}.${name}" "== ${want}" "${got_n:-error}" false
        fi
    done

    # Sequences non-reset: no never-called sequence may own a non-empty table.
    local seq_bad
    seq_bad=$(rq "$db" "
        SELECT COUNT(*) FROM pg_sequences ps
        JOIN pg_class seqc ON seqc.relname = ps.sequencename AND seqc.relkind = 'S'
        JOIN pg_namespace ns ON ns.oid = seqc.relnamespace AND ns.nspname = ps.schemaname
        JOIN pg_depend d ON d.objid = seqc.oid AND d.deptype IN ('a','i')
        JOIN pg_class tbl ON tbl.oid = d.refobjid AND tbl.relkind = 'r'
        WHERE ps.schemaname = 'public' AND ps.last_value IS NULL AND tbl.reltuples > 0")
    if [[ "$seq_bad" == "0" ]]; then
        check_add "${prefix}.sequences" "0 reset sequences on non-empty tables" "0" true
    else
        check_add "${prefix}.sequences" "0 reset sequences on non-empty tables" "${seq_bad:-error}" false
    fi

    # chat-api app-layer encrypted columns: fidelity vs the manifest
    # (decryption needs chat-api's ENCRYPTION_KEY and is out of drill scope).
    if [[ "$db" == "chat_api" ]]; then
        validate_encrypted_fidelity "$db"
    fi
}

# chat-api encrypted token columns, FIDELITY semantics: the manifest records
# per column how many values were NON NULL (total) and ciphertext-shaped per
# PG_CIPHERTEXT_REGEX (wellformed) at dump time; the restored database must
# show the same distribution. An absolute "everything ciphertext-shaped"
# check is wrong — staging legitimately carries dev-shaped token values, and
# the drill validates the RESTORE, not the source data. Manifests from
# before encrypted_format capture skip the check (SKIPPED-pass) rather than
# fail on source shape.
validate_encrypted_fidelity() {
    local db="$1"
    local encfmt
    encfmt=$(jq -c --arg db "$db" \
        '.databases[] | select(.name == $db) | .validation.encrypted_format // "absent"' \
        "$RESTORE_WORK_DIR/manifest.json")
    if [[ "$encfmt" == '"absent"' || -z "$encfmt" ]]; then
        check_add "chat_api.encrypted_columns_fidelity" \
            "token columns total+wellformed == manifest" \
            "manifest predates encrypted_format capture (check skipped)" true
        return 0
    fi

    local cols_total=0 bad="" key want_total want_well tbl col pair got_total got_well
    while IFS=$'\t' read -r key want_total want_well; do
        [[ -n "$key" ]] || continue
        cols_total=$(( cols_total + 1 ))
        tbl="${key%%.*}"
        col="${key#*.}"
        if ! valid_identifier "$tbl" || ! valid_identifier "$col"; then
            bad="${bad} ${key}(bad-identifier)"
            continue
        fi
        pair=$(rq "$db" "SELECT COUNT(\"${col}\") || ' ' || COUNT(*) FILTER (WHERE \"${col}\" ~ '${PG_CIPHERTEXT_REGEX}') FROM public.\"${tbl}\"") || pair=""
        got_total="${pair%% *}"
        got_well="${pair##* }"
        if [[ "$got_total" != "$want_total" || "$got_well" != "$want_well" ]]; then
            bad="${bad} ${col}:total=${got_total:-err}/${want_total},wellformed=${got_well:-err}/${want_well}"
        fi
    done < <(jq -r 'to_entries[] | [.key, (.value.total | tostring), (.value.wellformed | tostring)] | @tsv' \
        <<<"$encfmt")

    if (( cols_total == 0 )); then
        check_add "chat_api.encrypted_columns_fidelity" \
            "token columns total+wellformed == manifest" \
            "no encrypted columns recorded at dump time" true
    elif [[ -z "$bad" ]]; then
        check_add "chat_api.encrypted_columns_fidelity" \
            "token columns total+wellformed == manifest" \
            "${cols_total} columns, distribution matches" true
    else
        check_add "chat_api.encrypted_columns_fidelity" \
            "token columns total+wellformed == manifest" \
            "mismatch:${bad}" false
    fi
}

validate_rpo() {
    local backup_started started_epoch
    backup_started=$(jq -r '.started_at' "$RESTORE_WORK_DIR/manifest.json")
    started_epoch=$(date -u -d "$backup_started" +%s 2>/dev/null) || started_epoch=""
    if [[ -n "${RESTORE_NEWEST_CREATED_AT:-}" && -n "$started_epoch" ]]; then
        local newest_epoch age
        newest_epoch=$(date -u -d "$RESTORE_NEWEST_CREATED_AT" +%s 2>/dev/null) || newest_epoch=""
        if [[ -n "$newest_epoch" ]]; then
            age=$(( started_epoch - newest_epoch ))
            RESTORE_DATA_AGE_SECONDS="$age"
            if (( age < RESTORE_RPO_TARGET_SECONDS )); then
                check_add "cluster.rpo_freshness" \
                    "newest row < ${RESTORE_RPO_TARGET_SECONDS}s older than backup" "${age}s" true
            else
                check_add "cluster.rpo_freshness" \
                    "newest row < ${RESTORE_RPO_TARGET_SECONDS}s older than backup" "${age}s" false
            fi
            return 0
        fi
    fi
    check_add "cluster.rpo_freshness" "newest row age computable" "no created_at data available" false
}

validate_bucket_drift() {
    if [[ "$RESTORE_BUCKET_CHECK" != "true" ]]; then
        check_add "bucket.drift" "bucket config verification" "skipped (RESTORE_BUCKET_CHECK=false)" true
        return 0
    fi
    local bad="" v
    v=$(aws s3api get-bucket-versioning --bucket "$S3_BUCKET" --query Status --output text 2>/dev/null) || v=""
    [[ "$v" == "Enabled" ]] || bad="${bad} versioning=${v:-unset}"
    v=$(aws s3api get-object-lock-configuration --bucket "$S3_BUCKET" \
        --query 'ObjectLockConfiguration.Rule.DefaultRetention.Mode' --output text 2>/dev/null) || v=""
    [[ "$v" == "GOVERNANCE" ]] || bad="${bad} object-lock=${v:-unset}"
    v=$(aws s3api get-public-access-block --bucket "$S3_BUCKET" \
        --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' \
        --output text 2>/dev/null | tr '\t' ',') || v=""
    [[ "$v" == "True,True,True,True" ]] || bad="${bad} public-access-block=${v:-unset}"
    v=$(aws s3api get-bucket-encryption --bucket "$S3_BUCKET" \
        --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
        --output text 2>/dev/null) || v=""
    [[ "$v" == "AES256" ]] || bad="${bad} sse=${v:-unset}"
    v=$(aws s3api get-bucket-lifecycle-configuration --bucket "$S3_BUCKET" \
        --query 'length(Rules)' --output text 2>/dev/null) || v=""
    [[ "$v" =~ ^[0-9]+$ && "$v" -ge 1 ]] || bad="${bad} lifecycle-rules=${v:-unset}"

    if [[ -z "$bad" ]]; then
        check_add "bucket.drift" "versioning+object-lock+PAB+SSE+lifecycle as provisioned" "no drift" true
    else
        check_add "bucket.drift" "versioning+object-lock+PAB+SSE+lifecycle as provisioned" "drift:${bad}" false
    fi
}

validate_rto() {
    local total=$(( $(date +%s) - RESTORE_START_EPOCH ))
    if (( total < RESTORE_RTO_TARGET_SECONDS )); then
        check_add "cluster.rto_within_target" "total < ${RESTORE_RTO_TARGET_SECONDS}s" "${total}s" true
    else
        check_add "cluster.rto_within_target" "total < ${RESTORE_RTO_TARGET_SECONDS}s" "${total}s" false
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

restore_main() {
    log_info "pg-backup starting (mode: restore, drill: ${DRILL_ID:-unset})"
    restore_validate_env

    mkdir -p "$RESTORE_WORK_DIR/enc" "$RESTORE_WORK_DIR/plain"
    RESTORE_STDERR_DIR="$RESTORE_WORK_DIR/stderr"
    mkdir -p "$RESTORE_STDERR_DIR"
    RESTORE_CHECKS_FILE="$RESTORE_WORK_DIR/checks.ndjson"
    RESTORE_PHASES_FILE="$RESTORE_WORK_DIR/phases"
    : > "$RESTORE_CHECKS_FILE"
    : > "$RESTORE_PHASES_FILE"
    RESTORE_STARTED_AT=$(date -u +%FT%TZ)
    RESTORE_START_EPOCH=$(date +%s)
    # First S3 write of the driver: proves the driver is up AND has egress
    # before any long-running work begins.
    progress_put driver_started
    DRILL_PGPASSWORD="$RESTORE_PG_PASSWORD"
    trap restore_on_exit EXIT

    local hard_fail=0
    if restore_download \
        && restore_verify_ciphertext \
        && restore_decrypt \
        && restore_wait_pg \
        && restore_pg_major_gate \
        && restore_globals; then
        restore_databases
        local t0=$SECONDS db
        validate_cluster
        for db in "${RESTORE_DBS[@]}"; do
            validate_database "$db"
        done
        validate_rpo
        validate_bucket_drift
        phase_record validate $(( SECONDS - t0 ))
    else
        hard_fail=1
        log_error "Hard failure before restore battery completed"
    fi
    validate_rto

    local verdict
    verdict=$(restore_verdict)
    [[ "$hard_fail" -eq 1 ]] && verdict="FAIL"
    restore_report_write "$verdict"
    restore_report_upload || true

    local failed
    failed=$(jq -rs '[.[] | select(.pass | not) | .id] | join(", ")' "$RESTORE_CHECKS_FILE")
    log_info "Drill ${DRILL_ID} verdict: ${verdict}${failed:+ (failed checks: ${failed})}"
    trap - EXIT
    [[ "$verdict" == "PASS" ]]
}
