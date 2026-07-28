#!/usr/bin/env bash
# Prometheus metrics: a textfile rendered by the daemon, served on
# :$BACKUP_METRICS_PORT by socat (the postgres:16-alpine busybox has no httpd
# applet). The in-CVM otelcol docker_sd job scrapes it via the
# nearai.otel.scrape/port labels on the sidecar service.
#
# Cluster-level series (last_success, restore_test_*) are refreshed by the
# heartbeat from control/latest.json and the newest restore-reports/ object,
# so BOTH members serve them and alerts can use max() — the restore deadman
# keeps firing even if GitHub silently disables the drill cron.

METRICS_DIR="/run/metrics"
METRICS_FILE="${METRICS_DIR}/metrics"
METRICS_SERVER_PID=""
# Absolute path of this file: socat re-executes it as the per-connection
# responder (`bash lib/metrics.sh serve-once`) — a plain command string,
# because socat applies its own quote/escape processing to SYSTEM addresses.
METRICS_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

# Metric state (globals; empty = not yet known = series omitted).
M_LAST_SUCCESS_TS=""
M_LAST_RUN_TS=""
M_LAST_RUN_SUCCESS=""
M_LAST_RUN_DURATION=""
M_RUNS_SUCCESS_TOTAL=0
M_RUNS_FAILURE_TOTAL=0
M_RESTORE_LAST_SUCCESS_TS=""
M_RESTORE_LAST_STATUS=""
M_DUMP_SIZES_FILE="${METRICS_DIR}/dump_sizes"   # lines: "<database> <bytes>"

M_LAST_MANIFEST_KEY=""
M_LAST_RESTORE_REPORT_KEY=""
M_RESTORE_FETCH_WARNED=0

metrics_init() {
    mkdir -p "$METRICS_DIR"
    : > "$M_DUMP_SIZES_FILE"
    metrics_render "$METRICS_FILE"
}

# Render the textfile atomically. Gauges with unknown ("") values are
# omitted so absent() alerting keeps working; counters always render.
metrics_render() {
    local out="${1:-$METRICS_FILE}"
    local tmp="${out}.tmp"
    {
        if [[ -n "$M_LAST_SUCCESS_TS" ]]; then
            echo "# HELP nearai_postgres_backup_last_success_timestamp_seconds Completion time of the newest successful backup (from control/latest.json)."
            echo "# TYPE nearai_postgres_backup_last_success_timestamp_seconds gauge"
            echo "nearai_postgres_backup_last_success_timestamp_seconds $M_LAST_SUCCESS_TS"
        fi
        if [[ -n "$M_LAST_RUN_TS" ]]; then
            echo "# HELP nearai_postgres_backup_last_run_timestamp_seconds Start time of the most recent local backup attempt."
            echo "# TYPE nearai_postgres_backup_last_run_timestamp_seconds gauge"
            echo "nearai_postgres_backup_last_run_timestamp_seconds $M_LAST_RUN_TS"
        fi
        if [[ -n "$M_LAST_RUN_SUCCESS" ]]; then
            echo "# HELP nearai_postgres_backup_last_run_success Whether the most recent local backup attempt succeeded (1/0)."
            echo "# TYPE nearai_postgres_backup_last_run_success gauge"
            echo "nearai_postgres_backup_last_run_success $M_LAST_RUN_SUCCESS"
        fi
        if [[ -n "$M_LAST_RUN_DURATION" ]]; then
            echo "# HELP nearai_postgres_backup_last_run_duration_seconds Duration of the most recent local backup attempt."
            echo "# TYPE nearai_postgres_backup_last_run_duration_seconds gauge"
            echo "nearai_postgres_backup_last_run_duration_seconds $M_LAST_RUN_DURATION"
        fi
        if [[ -s "$M_DUMP_SIZES_FILE" ]]; then
            echo "# HELP nearai_postgres_backup_dump_size_bytes Plaintext dump size per database from the newest manifest (_globals = globals dump)."
            echo "# TYPE nearai_postgres_backup_dump_size_bytes gauge"
            local db bytes
            while read -r db bytes; do
                [[ -n "$db" && "$bytes" =~ ^[0-9]+$ ]] || continue
                echo "nearai_postgres_backup_dump_size_bytes{database=\"${db}\"} ${bytes}"
            done < "$M_DUMP_SIZES_FILE"
        fi
        echo "# HELP nearai_postgres_backup_runs_total Local backup attempts by result."
        echo "# TYPE nearai_postgres_backup_runs_total counter"
        echo "nearai_postgres_backup_runs_total{result=\"success\"} $M_RUNS_SUCCESS_TOTAL"
        echo "nearai_postgres_backup_runs_total{result=\"failure\"} $M_RUNS_FAILURE_TOTAL"
        if [[ -n "$M_RESTORE_LAST_SUCCESS_TS" ]]; then
            echo "# HELP nearai_postgres_restore_test_last_success_timestamp_seconds Completion time of the newest PASS restore drill report."
            echo "# TYPE nearai_postgres_restore_test_last_success_timestamp_seconds gauge"
            echo "nearai_postgres_restore_test_last_success_timestamp_seconds $M_RESTORE_LAST_SUCCESS_TS"
        fi
        if [[ -n "$M_RESTORE_LAST_STATUS" ]]; then
            echo "# HELP nearai_postgres_restore_test_last_status Verdict of the newest restore drill report (1 PASS / 0 FAIL)."
            echo "# TYPE nearai_postgres_restore_test_last_status gauge"
            echo "nearai_postgres_restore_test_last_status $M_RESTORE_LAST_STATUS"
        fi
    } > "$tmp"
    mv "$tmp" "$out"
}

metrics_server_start() {
    socat -T 10 TCP-LISTEN:"${BACKUP_METRICS_PORT}",fork,reuseaddr \
        SYSTEM:"bash ${METRICS_SELF} serve-once" &
    METRICS_SERVER_PID=$!
    log_info "Metrics server listening on :${BACKUP_METRICS_PORT}"
}

metrics_server_stop() {
    if [[ -n "$METRICS_SERVER_PID" ]]; then
        kill "$METRICS_SERVER_PID" 2>/dev/null || true
        wait "$METRICS_SERVER_PID" 2>/dev/null || true
        METRICS_SERVER_PID=""
    fi
}

# Refresh cluster-level series from S3. Never fails the caller.
metrics_heartbeat() {
    local latest completed manifest_key manifest
    latest=$(latest_fetch) || latest=""
    if [[ -n "$latest" ]]; then
        completed=$(jq -r '.completed_at // empty' <<<"$latest" 2>/dev/null) || completed=""
        if [[ -n "$completed" ]]; then
            M_LAST_SUCCESS_TS=$(date -u -d "$completed" +%s 2>/dev/null) || M_LAST_SUCCESS_TS=""
        fi
        manifest_key=$(jq -r '.manifest_key // empty' <<<"$latest" 2>/dev/null) || manifest_key=""
        if [[ -n "$manifest_key" && "$manifest_key" != "$M_LAST_MANIFEST_KEY" ]]; then
            manifest=$(s3_get_stdout "$manifest_key" 2>/dev/null) || manifest=""
            if [[ -n "$manifest" ]]; then
                {
                    jq -r '.databases[] | "\(.name) \(.size_bytes_plaintext)"' <<<"$manifest" 2>/dev/null
                    jq -r '"_globals \(.globals.size_bytes_plaintext)"' <<<"$manifest" 2>/dev/null
                } > "${M_DUMP_SIZES_FILE}.tmp" && mv "${M_DUMP_SIZES_FILE}.tmp" "$M_DUMP_SIZES_FILE"
                M_LAST_MANIFEST_KEY="$manifest_key"
            fi
        fi
    fi

    # Newest restore drill report (DRILL_ID keys sort chronologically).
    local report_key report verdict
    report_key=$(s3_list_keys "restore-reports/" | tail -n 1) || report_key=""
    if [[ -n "$report_key" && "$report_key" != "$M_LAST_RESTORE_REPORT_KEY" ]]; then
        report=$(s3_get_stdout "$report_key" 2>/dev/null) || report=""
        if [[ -n "$report" ]]; then
            verdict=$(jq -r '.verdict // empty' <<<"$report" 2>/dev/null) || verdict=""
            completed=$(jq -r '.completed_at // empty' <<<"$report" 2>/dev/null) || completed=""
            if [[ "$verdict" == "PASS" ]]; then
                M_RESTORE_LAST_STATUS=1
                [[ -n "$completed" ]] \
                    && M_RESTORE_LAST_SUCCESS_TS=$(date -u -d "$completed" +%s 2>/dev/null)
            elif [[ -n "$verdict" ]]; then
                M_RESTORE_LAST_STATUS=0
            fi
            M_LAST_RESTORE_REPORT_KEY="$report_key"
        elif [[ "$M_RESTORE_FETCH_WARNED" -eq 0 ]]; then
            # Expected if the writer principal is not granted read on
            # restore-reports/ — the restore deadman series stays absent.
            log_warn "Cannot read ${report_key}; restore drill metrics unavailable"
            M_RESTORE_FETCH_WARNED=1
        fi
    fi

    metrics_render "$METRICS_FILE"
    return 0
}

# Executed (not sourced) by socat per scrape connection: drain the request
# headers, then emit one HTTP response with the current textfile.
if [[ "${BASH_SOURCE[0]}" == "${0}" && "${1:-}" == "serve-once" ]]; then
    while IFS= read -r -t 5 _line; do
        _line="${_line%$'\r'}"
        [[ -z "$_line" ]] && break
    done
    printf 'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n'
    cat "${METRICS_FILE}" 2>/dev/null || true
    exit 0
fi
