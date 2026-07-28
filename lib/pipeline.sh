#!/usr/bin/env bash
# Streaming dump pipeline. No plaintext ever touches disk: pg_dump streams
# through openssl straight into `aws s3 cp -`. sha256/size taps hang off the
# stream via FIFOs on tmpfs so both plaintext and ciphertext digests are
# captured without buffering the dump anywhere.
#
#   pg_dump -Fc db | tee plain-taps | openssl enc | tee cipher-taps | aws s3 cp -
#
# Every pipeline stage's exit code is checked (pipefail + PIPESTATUS) and the
# tap files are asserted non-empty — a silently-broken tap must fail the run,
# not produce a manifest with empty checksums.

# Fetch the AES-256 key. Default source is the dstack guest agent socket
# (deterministic per app_id + key path — the restore drill under the same
# app_id re-derives it; rotation = key-path bump). BACKUP_KEY_SOURCE=env is a
# test-only escape hatch (e2e harness, no TEE). The key lives in process env
# only: never on disk, never in the CVM env file, never logged.
fetch_encryption_key() {
    local key_path="$1"
    case "${BACKUP_KEY_SOURCE:-dstack}" in
        dstack)
            if [[ ! -S /var/run/dstack.sock ]]; then
                log_error "dstack socket not found at /var/run/dstack.sock"
                return 1
            fi
            BACKUP_ENCRYPTION_KEY=$(curl -s --unix-socket /var/run/dstack.sock \
                "http://localhost/GetKey?path=${key_path}" | jq -r '.key' | head -c 64)
            if [[ -z "$BACKUP_ENCRYPTION_KEY" || "$BACKUP_ENCRYPTION_KEY" == "null" ]]; then
                log_error "Failed to derive encryption key from dstack (path: ${key_path})"
                return 1
            fi
            export BACKUP_ENCRYPTION_KEY
            log_info "Encryption key derived (path: ${key_path})"
            ;;
        env)
            if [[ -z "${BACKUP_ENCRYPTION_KEY:-}" ]]; then
                log_error "BACKUP_KEY_SOURCE=env but BACKUP_ENCRYPTION_KEY is not set"
                return 1
            fi
            export BACKUP_ENCRYPTION_KEY
            log_warn "Using encryption key from environment (test escape hatch)"
            ;;
        *)
            log_error "Unknown BACKUP_KEY_SOURCE '${BACKUP_KEY_SOURCE}'"
            return 1
            ;;
    esac
}

# Internal: run `<producer> | tee taps | openssl | tee taps | aws s3 cp -`.
# The producer command is passed as trailing args. Results are exported via
# globals PIPE_PLAIN_SHA / PIPE_PLAIN_SIZE / PIPE_CIPHER_SHA / PIPE_CIPHER_SIZE.
# All stderr goes to per-stage files under $tap_dir (content-bearing, tmpfs).
pipeline_stream_encrypt_upload() {
    local tap_dir="$1"
    local s3_key="$2"
    local expected_size="$3"
    shift 3

    PIPE_PLAIN_SHA="" PIPE_PLAIN_SIZE="" PIPE_CIPHER_SHA="" PIPE_CIPHER_SIZE=""

    local f
    for f in plain.sha plain.size cipher.sha cipher.size; do
        rm -f "${tap_dir}/${f}.fifo" "${tap_dir}/${f}"
        mkfifo "${tap_dir}/${f}.fifo"
    done

    # Tap consumers: explicit background jobs (not process substitution) so
    # they can be waited on — otherwise the tap files may not be flushed when
    # the pipeline returns.
    sha256sum <"${tap_dir}/plain.sha.fifo" >"${tap_dir}/plain.sha" &
    local pid_psha=$!
    wc -c <"${tap_dir}/plain.size.fifo" >"${tap_dir}/plain.size" &
    local pid_psize=$!
    sha256sum <"${tap_dir}/cipher.sha.fifo" >"${tap_dir}/cipher.sha" &
    local pid_csha=$!
    wc -c <"${tap_dir}/cipher.size.fifo" >"${tap_dir}/cipher.size" &
    local pid_csize=$!

    # PIPESTATUS must be captured on the line immediately after the pipeline,
    # and set -e must not abort before that capture.
    local had_errexit=0
    [[ $- == *e* ]] && had_errexit=1
    set +e
    "$@" 2>"${tap_dir}/producer.stderr" \
        | tee "${tap_dir}/plain.sha.fifo" "${tap_dir}/plain.size.fifo" \
        | openssl enc -aes-256-cbc -salt -pbkdf2 -pass env:BACKUP_ENCRYPTION_KEY \
            2>"${tap_dir}/openssl.stderr" \
        | tee "${tap_dir}/cipher.sha.fifo" "${tap_dir}/cipher.size.fifo" \
        | s3_put_stream "$s3_key" "$expected_size" 2>"${tap_dir}/aws.stderr"
    local stage_status=("${PIPESTATUS[@]}")
    [[ "$had_errexit" -eq 1 ]] && set -e

    wait "$pid_psha" "$pid_psize" "$pid_csha" "$pid_csize" 2>/dev/null || true
    rm -f "${tap_dir}"/*.fifo

    local i
    for i in "${!stage_status[@]}"; do
        if [[ "${stage_status[$i]}" -ne 0 ]]; then
            log_error "Pipeline stage $i exited ${stage_status[$i]} for ${s3_key}" \
                "(producer stderr: $(stderr_summarize "${tap_dir}/producer.stderr");" \
                "openssl: $(stderr_summarize "${tap_dir}/openssl.stderr");" \
                "aws: $(stderr_summarize "${tap_dir}/aws.stderr"))"
            return 1
        fi
    done

    # Tap-file non-empty guards.
    for f in plain.sha plain.size cipher.sha cipher.size; do
        if [[ ! -s "${tap_dir}/${f}" ]]; then
            log_error "Pipeline tap ${f} is empty for ${s3_key}"
            return 1
        fi
    done

    # Globals consumed by the caller (manifest construction in entrypoint.sh).
    # shellcheck disable=SC2034
    PIPE_PLAIN_SHA=$(awk '{print $1}' "${tap_dir}/plain.sha")
    PIPE_PLAIN_SIZE=$(awk '{print $1}' "${tap_dir}/plain.size")
    # shellcheck disable=SC2034
    PIPE_CIPHER_SHA=$(awk '{print $1}' "${tap_dir}/cipher.sha")
    # shellcheck disable=SC2034
    PIPE_CIPHER_SIZE=$(awk '{print $1}' "${tap_dir}/cipher.size")

    if [[ ! "$PIPE_PLAIN_SIZE" =~ ^[0-9]+$ ]] || (( PIPE_PLAIN_SIZE == 0 )); then
        log_error "Pipeline produced zero plaintext bytes for ${s3_key}"
        return 1
    fi

    if [[ -s "${tap_dir}/producer.stderr" ]]; then
        log_warn "Producer stderr for ${s3_key}: $(stderr_summarize "${tap_dir}/producer.stderr")"
    fi
    return 0
}

# Dump one database: pg_dump -Fc streamed to backups/<id>/<db>.dump.enc.
#   $1 = database  $2 = s3 key  $3 = tap dir (tmpfs)  $4 = deadline epoch
#   $5 = snapshot id ("" = no --snapshot)
pipeline_dump_database() {
    local db="$1"
    local s3_key="$2"
    local tap_dir="$3"
    local deadline="$4"
    local snapshot="${5:-}"

    local db_size remaining
    db_size=$(pg_database_size "$db")
    [[ "$db_size" =~ ^[0-9]+$ ]] || db_size=""
    remaining=$(( deadline - $(date +%s) ))
    if (( remaining < 60 )); then
        log_error "Run timeout budget exhausted before dumping ${db}"
        return 1
    fi

    # Idle-priority the dump (probe once: ionice idle class can be denied in
    # restricted containers, and a failed prefix must not fail the backup).
    if [[ -z "${PIPELINE_NICE_PROBED:-}" ]]; then
        if ionice -c3 true 2>/dev/null; then
            PIPELINE_NICE=(nice -n 19 ionice -c3)
        else
            PIPELINE_NICE=(nice -n 19)
        fi
        PIPELINE_NICE_PROBED=1
    fi

    local -a dump_cmd=(
        timeout -k 30 "$remaining"
        "${PIPELINE_NICE[@]}"
        pg_dump -h "$BACKUP_PG_HOST" -p "$BACKUP_PG_PORT" -U postgres -Fc
    )
    if [[ -n "$snapshot" ]]; then
        dump_cmd+=(--snapshot="$snapshot")
    fi
    dump_cmd+=("$db")

    PGPASSWORD="$(pg_password)" PGAPPNAME="nearai-backup" \
        PGOPTIONS="-c lock_timeout=30s -c statement_timeout=0" \
        pipeline_stream_encrypt_upload "$tap_dir" "$s3_key" "$db_size" "${dump_cmd[@]}"
}

# Dump cluster globals: pg_dumpall --globals-only | gzip, streamed to
# backups/<id>/globals.sql.gz.enc. The manifest's plaintext sha256 covers the
# gzip bytes (what the drill decrypts, verifies, then gunzips).
pipeline_dump_globals() {
    local s3_key="$1"
    local tap_dir="$2"
    local deadline="$3"

    local remaining
    remaining=$(( deadline - $(date +%s) ))
    if (( remaining < 60 )); then
        log_error "Run timeout budget exhausted before dumping globals"
        return 1
    fi

    # shellcheck disable=SC2016  # expanded by the child bash, not here
    PGPASSWORD="$(pg_password)" PGAPPNAME="nearai-backup" \
        PGOPTIONS="-c lock_timeout=30s -c statement_timeout=0" \
        pipeline_stream_encrypt_upload "$tap_dir" "$s3_key" "" \
        timeout -k 30 "$remaining" bash -c \
        'pg_dumpall --globals-only -h "$BACKUP_PG_HOST" -p "$BACKUP_PG_PORT" -U postgres | gzip -n'
}
