#!/usr/bin/env bats
# Metrics textfile rendering: contract series names, label shapes, and the
# omit-when-unknown rule (absent() alerting depends on it).

load test_helper

setup() {
    source_entrypoint
    OUT="$BATS_TEST_TMPDIR/metrics"
    M_DUMP_SIZES_FILE="$BATS_TEST_TMPDIR/dump_sizes"
    : > "$M_DUMP_SIZES_FILE"
}

@test "render: counters always present, unknown gauges omitted" {
    metrics_render "$OUT"
    grep -q 'nearai_postgres_backup_runs_total{result="success"} 0' "$OUT"
    grep -q 'nearai_postgres_backup_runs_total{result="failure"} 0' "$OUT"
    ! grep -q 'nearai_postgres_backup_last_success_timestamp_seconds' "$OUT"
    ! grep -q 'nearai_postgres_restore_test_last_status' "$OUT"
}

@test "render: full state renders every contract series" {
    M_LAST_SUCCESS_TS=1753660000
    M_LAST_RUN_TS=1753660100
    M_LAST_RUN_SUCCESS=1
    M_LAST_RUN_DURATION=812
    M_RUNS_SUCCESS_TOTAL=4
    M_RUNS_FAILURE_TOTAL=1
    M_RESTORE_LAST_SUCCESS_TS=1753500000
    M_RESTORE_LAST_STATUS=1
    printf 'postgres 123456\nchat_api 7890\n_globals 4321\n' > "$M_DUMP_SIZES_FILE"

    metrics_render "$OUT"

    grep -q '^nearai_postgres_backup_last_success_timestamp_seconds 1753660000$' "$OUT"
    grep -q '^nearai_postgres_backup_last_run_timestamp_seconds 1753660100$' "$OUT"
    grep -q '^nearai_postgres_backup_last_run_success 1$' "$OUT"
    grep -q '^nearai_postgres_backup_last_run_duration_seconds 812$' "$OUT"
    grep -q '^nearai_postgres_backup_dump_size_bytes{database="postgres"} 123456$' "$OUT"
    grep -q '^nearai_postgres_backup_dump_size_bytes{database="chat_api"} 7890$' "$OUT"
    grep -q '^nearai_postgres_backup_dump_size_bytes{database="_globals"} 4321$' "$OUT"
    grep -q '^nearai_postgres_backup_runs_total{result="success"} 4$' "$OUT"
    grep -q '^nearai_postgres_backup_runs_total{result="failure"} 1$' "$OUT"
    grep -q '^nearai_postgres_restore_test_last_success_timestamp_seconds 1753500000$' "$OUT"
    grep -q '^nearai_postgres_restore_test_last_status 1$' "$OUT"
}

@test "render: HELP/TYPE lines accompany rendered series" {
    M_LAST_RUN_SUCCESS=0
    metrics_render "$OUT"
    grep -q '^# HELP nearai_postgres_backup_last_run_success ' "$OUT"
    grep -q '^# TYPE nearai_postgres_backup_last_run_success gauge$' "$OUT"
    grep -q '^# TYPE nearai_postgres_backup_runs_total counter$' "$OUT"
}

@test "render: malformed dump-size lines are skipped" {
    printf 'postgres 100\nbroken-line\nchat_api notanumber\n' > "$M_DUMP_SIZES_FILE"
    metrics_render "$OUT"
    grep -q '^nearai_postgres_backup_dump_size_bytes{database="postgres"} 100$' "$OUT"
    [ "$(grep -c '^nearai_postgres_backup_dump_size_bytes' "$OUT")" = "1" ]
}

@test "render: atomic write leaves no tmp file" {
    metrics_render "$OUT"
    [ ! -e "${OUT}.tmp" ]
}
