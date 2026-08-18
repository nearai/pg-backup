#!/usr/bin/env bats
# Privacy-safe restore diagnostics: fixed category counts, bounded sampling,
# and no durable propagation of captured stderr.

load test_helper

setup() {
    source_entrypoint
    source "$(repo_root)/lib/restore.sh"
    RESTORE_STDERR_DIR="$BATS_TEST_TMPDIR/stderr"
    mkdir -p "$RESTORE_STDERR_DIR"
    RESTORE_PROFILE="legacy-v1"
    RESTORE_POSTMASTER_START_PRE=""
    RESTORE_POSTMASTER_START_POST=""
    RESTORE_SCRATCH_DISK_USED_PERCENT=""
}

@test "restore_diagnostics_build: emits only bounded safe categories without captured canaries" {
    cat > "$RESTORE_STDERR_DIR/restore.stderr" <<'EOF'
psql: error: server closed the connection unexpectedly password=FORBIDDEN_PASSWORD
pg_restore: error: could not write to file "/forbidden/private/path": No space left on device
pg_restore: error: could not fork new process: Resource temporarily unavailable
pg_restore: error: out of memory while processing schema forbidden_schema
CONTEXT: COPY private_table, line 7: "FORBIDDEN_ROW_VALUE"
STATEMENT: SELECT forbidden_column FROM forbidden_schema.private_table
EOF
    RESTORE_POSTMASTER_START_PRE=100
    RESTORE_POSTMASTER_START_POST=101
    RESTORE_SCRATCH_DISK_USED_PERCENT=90

    local diagnostics
    diagnostics=$(restore_diagnostics_build)

    [ "$(jq -c 'keys | sort' <<<"$diagnostics")" = \
        '["failure_category_counts","failure_category_counts_truncated","postgres_restart_observed","restore_profile","scratch_disk_pressure","scratch_disk_used_percent"]' ]
    [ "$(jq -c '.failure_category_counts' <<<"$diagnostics")" = \
        '{"connection":1,"disk":1,"resource":2}' ]
    [ "$(jq -r '.failure_category_counts_truncated' <<<"$diagnostics")" = "false" ]
    [ "$(jq -r '.postgres_restart_observed' <<<"$diagnostics")" = "true" ]
    [ "$(jq -r '.scratch_disk_pressure' <<<"$diagnostics")" = "high" ]
    [ "$(jq -r '.scratch_disk_used_percent' <<<"$diagnostics")" = "90" ]
    ! grep -Eq 'FORBIDDEN|private_table|forbidden_schema|forbidden_column|/forbidden' <<<"$diagnostics"
}

@test "restore_diagnostics_build: category counts saturate at the named 20000-line limit" {
    [ "$RESTORE_DIAGNOSTIC_LINE_LIMIT" = "20000" ]
    RESTORE_DIAGNOSTIC_LINE_LIMIT=3
    awk 'BEGIN { for (i = 1; i <= 4; i++) print "server closed the connection unexpectedly" }' \
        > "$RESTORE_STDERR_DIR/restore.stderr"

    local diagnostics
    diagnostics=$(restore_diagnostics_build)

    [ "$(jq -r '.failure_category_counts.connection' <<<"$diagnostics")" = "3" ]
    [ "$(jq -r '.failure_category_counts.disk' <<<"$diagnostics")" = "0" ]
    [ "$(jq -r '.failure_category_counts.resource' <<<"$diagnostics")" = "0" ]
    [ "$(jq -r '.failure_category_counts_truncated' <<<"$diagnostics")" = "true" ]
}

@test "restore_diagnostics_build: restart is false only for two equal valid samples" {
    RESTORE_POSTMASTER_START_PRE=100
    RESTORE_POSTMASTER_START_POST=100
    [ "$(restore_diagnostics_build | jq -r '.postgres_restart_observed')" = "false" ]

    RESTORE_POSTMASTER_START_POST=101
    [ "$(restore_diagnostics_build | jq -r '.postgres_restart_observed')" = "true" ]

    RESTORE_POSTMASTER_START_PRE=""
    [ "$(restore_diagnostics_build | jq -r '.postgres_restart_observed')" = "unknown" ]

    RESTORE_POSTMASTER_START_PRE=invalid
    RESTORE_POSTMASTER_START_POST=101
    [ "$(restore_diagnostics_build | jq -r '.postgres_restart_observed')" = "unknown" ]
}

@test "restore_diagnostics_build: scratch pressure uses the named 90-percent boundary and unknown omits usage" {
    [ "$RESTORE_SCRATCH_DISK_PRESSURE_PERCENT" = "90" ]

    RESTORE_SCRATCH_DISK_USED_PERCENT=89
    [ "$(restore_diagnostics_build | jq -r '.scratch_disk_pressure')" = "normal" ]
    [ "$(restore_diagnostics_build | jq -r '.scratch_disk_used_percent')" = "89" ]

    RESTORE_SCRATCH_DISK_USED_PERCENT=90
    [ "$(restore_diagnostics_build | jq -r '.scratch_disk_pressure')" = "high" ]
    [ "$(restore_diagnostics_build | jq -r '.scratch_disk_used_percent')" = "90" ]

    RESTORE_SCRATCH_DISK_USED_PERCENT=""
    [ "$(restore_diagnostics_build | jq -r '.scratch_disk_pressure')" = "unknown" ]
    [ "$(restore_diagnostics_build | jq -r 'has("scratch_disk_used_percent")')" = "false" ]
}

@test "restore_report_write: adds diagnostics without changing the legacy envelope or verdict" {
    RESTORE_WORK_DIR="$BATS_TEST_TMPDIR/report-work"
    RESTORE_STDERR_DIR="$RESTORE_WORK_DIR/stderr"
    RESTORE_CHECKS_FILE="$RESTORE_WORK_DIR/checks.ndjson"
    RESTORE_PHASES_FILE="$RESTORE_WORK_DIR/phases"
    mkdir -p "$RESTORE_STDERR_DIR"
    : > "$RESTORE_CHECKS_FILE"
    : > "$RESTORE_PHASES_FILE"
    RESTORE_STARTED_AT="2026-01-01T00:10:00Z"
    RESTORE_START_EPOCH=$(date +%s)
    RESTORE_MANIFEST_KEY="backups/synthetic/manifest.json"
    RESTORE_RPO_TARGET_SECONDS=86400
    RESTORE_RTO_TARGET_SECONDS=14400
    RESTORE_DATA_AGE_SECONDS=60
    RESTORE_ERROR_CLASSES='{}'
    RESTORE_SIZES='{}'
    RESTORE_NOTES='[]'
    RESTORE_POSTMASTER_START_PRE=""
    RESTORE_POSTMASTER_START_POST=101
    RESTORE_SCRATCH_DISK_USED_PERCENT=""
    jq -n '{format_version: 2, backup_id: "synthetic-backup",
            started_at: "2026-01-01T00:00:00Z",
            completed_at: "2026-01-01T00:05:00Z"}' \
        > "$RESTORE_WORK_DIR/manifest.json"
    check_add "cluster.manifest_complete" "manifest_complete" "manifest_invalid" false
    printf '%s\n' 'server closed the connection unexpectedly FORBIDDEN_VALUE' \
        > "$RESTORE_STDERR_DIR/restore.stderr"

    restore_report_write FAIL

    local report="$RESTORE_WORK_DIR/report.json"
    [ "$(jq -c 'keys | sort' "$report")" = \
        '["backup","checks","completed_at","diagnostics","drill_id","error_classes","format_version","notes","rpo","rto","sizes","started_at","verdict"]' ]
    [ "$(jq -r '.diagnostics.restore_profile' "$report")" = "legacy-v1" ]
    [ "$(jq -r '.diagnostics.failure_category_counts.connection' "$report")" = "1" ]
    [ "$(jq -r '.diagnostics.postgres_restart_observed' "$report")" = "unknown" ]
    [ "$(jq -r '.verdict' "$report")" = "FAIL" ]
    [ "$(jq -r '.checks | length' "$report")" = "1" ]
    ! grep -q 'FORBIDDEN_VALUE' "$report"
}

@test "canonical restore report fixtures: production generator is deterministic and privacy-safe" {
    local generated="$BATS_TEST_TMPDIR/generated" fixture report expected_verdict
    mkdir -p "$generated"
    FIXTURE_OUTPUT_DIR="$generated" \
        "$(repo_root)/tests/fixtures/generate-restore-report-fixtures.sh" >/dev/null

    for fixture in restore-report-pass.json restore-report-fail.json; do
        report="$(repo_root)/tests/fixtures/$fixture"
        diff -u "$report" "$generated/$fixture"
        [ "$(jq -r '.checks | length' "$report")" = "36" ]
        diff -u "$(repo_root)/tests/fixtures/restore-check-ids.txt" \
            <(jq -r '.checks[].id' "$report")
        [ "$(jq -r '.diagnostics.restore_profile' "$report")" = "legacy-v1" ]
        [ "$(jq -r '.diagnostics.failure_category_counts
            | [.connection, .disk, .resource]
            | all(type == "number" and . >= 0 and . <= 20000)' "$report")" = "true" ]
        [ "$(jq -r '.diagnostics.scratch_disk_used_percent
            | type == "number" and . >= 0 and . <= 100' "$report")" = "true" ]
        ! grep -Eq 'FORBIDDEN|COPY|SELECT|password|private_table|/forbidden' "$report"

        expected_verdict=PASS
        [[ "$fixture" == *fail* ]] && expected_verdict=FAIL
        [ "$(jq -r '.verdict' "$report")" = "$expected_verdict" ]
        [ "$(jq -r '[.checks[] | select(.pass | not)] | length' "$report")" = \
            "$([[ "$expected_verdict" == PASS ]] && echo 0 || echo 1)" ]
    done
}
