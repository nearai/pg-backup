#!/usr/bin/env bats
# Restore-drill validation semantics: Spilo-artifact tolerance classifier,
# public-schema-scoped structural counts (symmetric with the backup side),
# and encrypted-column fidelity vs the manifest.

load test_helper

setup() {
    source_entrypoint
    # The entrypoint only sources the driver in restore mode; the unit tests
    # load it directly (definitions only — restore_main is never invoked).
    source "$(repo_root)/lib/restore.sh"
}

legacy_report_setup() {
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
    RESTORE_ERROR_CLASSES='{"cloud_api":"1 lines (other:1)"}'
    RESTORE_SIZES='{"cloud_api":{"plaintext_bytes":1,"ciphertext_bytes":2}}'
    RESTORE_NOTES='[]'

    jq -n \
        --arg backup_id "2026-01-01T0000Z-synthetic" \
        --arg started_at "2026-01-01T00:00:00Z" \
        --arg completed_at "2026-01-01T00:05:00Z" \
        '{format_version: 2, backup_id: $backup_id,
          started_at: $started_at, completed_at: $completed_at}' \
        > "$RESTORE_WORK_DIR/manifest.json"

    jq -c '.checks[]' "$(repo_root)/tests/fixtures/restore-report-pass.json" \
        > "$RESTORE_CHECKS_FILE"
}

@test "restore_report_write: legacy envelope, identity, RPO/RTO, hashes, and 36 checks stay intact" {
    legacy_report_setup

    restore_report_write PASS

    local report="$RESTORE_WORK_DIR/report.json"
    [ "$(jq -c 'del(.diagnostics) | keys | sort' "$report")" = \
        '["backup","checks","completed_at","drill_id","error_classes","format_version","notes","rpo","rto","sizes","started_at","verdict"]' ]
    [ "$(jq -r '.format_version' "$report")" = "1" ]
    [ "$(jq -r '.backup.backup_id' "$report")" = "2026-01-01T0000Z-synthetic" ]
    [ "$(jq -r '.backup.manifest_key' "$report")" = "backups/synthetic/manifest.json" ]
    [[ "$(jq -r '.backup.manifest_sha256' "$report")" =~ ^[0-9a-f]{64}$ ]]
    [ "$(jq -r '.rpo.data_age_seconds' "$report")" = "60" ]
    [ "$(jq -r '.rpo.target_seconds' "$report")" = "86400" ]
    [ "$(jq -r '.rto.target_seconds' "$report")" = "14400" ]
    [ "$(jq -r '.checks | length' "$report")" = "36" ]
    diff -u "$(repo_root)/tests/fixtures/restore-check-ids.txt" \
        <(jq -r '.checks[].id' "$report")
    [ "$(jq -r '.verdict' "$report")" = "PASS" ]
}

# ---------------------------------------------------------------------------
# restore_classify_errors: Spilo whitelist tolerance
# ---------------------------------------------------------------------------

@test "classify_errors: Spilo missing objects are tolerated, not blocking" {
    local f="$BATS_TEST_TMPDIR/stderr"
    {
        echo 'pg_restore: error: could not execute query: ERROR:  extension "bg_mon" is not available'
        echo 'pg_restore: error: could not execute query: ERROR:  extension "pg_auth_mon" does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  schema "metric_helpers" does not exist'
        echo 'LINE 1: CREATE VIEW metric_helpers.pg_stat_statements AS ...'
        echo 'pg_restore: error: could not execute query: ERROR:  function metric_helpers.get_btree_bloat_approx(boolean) does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  relation "user_management.users" does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  role "robot_zmon" does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  schema "zalando" does not exist'
    } > "$f"
    restore_classify_errors "$f"
    [ "$RESTORE_ERR_TOTAL" = "7" ]
    [ "$RESTORE_ERR_TOLERATED" = "7" ]
    [ "$RESTORE_ERR_BLOCKING" = "0" ]
}

@test "classify_errors: non-Spilo missing objects stay blocking" {
    local f="$BATS_TEST_TMPDIR/stderr"
    {
        echo 'pg_restore: error: could not execute query: ERROR:  relation "public.users" does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  extension "uuid-ossp" is not available'
        echo 'pg_restore: error: could not execute query: ERROR:  role "app_user" does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  schema "app_private" does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  function public.compute_totals(integer) does not exist'
    } > "$f"
    restore_classify_errors "$f"
    [ "$RESTORE_ERR_TOTAL" = "5" ]
    [ "$RESTORE_ERR_TOLERATED" = "0" ]
    [ "$RESTORE_ERR_BLOCKING" = "5" ]
}

@test "classify_errors: mixed stderr splits tolerated vs blocking" {
    local f="$BATS_TEST_TMPDIR/stderr"
    {
        echo 'pg_restore: error: could not execute query: ERROR:  extension "pg_cron" is not available'
        echo 'pg_restore: error: could not execute query: ERROR:  extension "pg_stat_kcache" is not available'
        echo 'pg_restore: error: could not execute query: ERROR:  relation "public.orders" does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  duplicate key value violates unique constraint "users_pkey"'
    } > "$f"
    restore_classify_errors "$f"
    [ "$RESTORE_ERR_TOTAL" = "4" ]
    [ "$RESTORE_ERR_TOLERATED" = "2" ]
    [ "$RESTORE_ERR_BLOCKING" = "2" ]
}

@test "classify_errors: cascading detail lines are not counted as errors" {
    local f="$BATS_TEST_TMPDIR/stderr"
    {
        echo 'pg_restore: error: could not execute query: ERROR:  schema "metric_helpers" does not exist'
        echo 'Command was: CREATE FUNCTION metric_helpers.get_table_bloat() ...'
        echo 'DETAIL:  some cascading context'
        echo 'HINT:  create the schema first'
        echo 'LINE 1: SELECT * FROM metric_helpers.pg_stat_statements'
        echo 'pg_restore: warning: errors ignored on restore: 30'
    } > "$f"
    restore_classify_errors "$f"
    [ "$RESTORE_ERR_TOTAL" = "1" ]
    [ "$RESTORE_ERR_TOLERATED" = "1" ]
    [ "$RESTORE_ERR_BLOCKING" = "0" ]
}

@test "classify_errors: tolerated summary retains only fixed kind counts" {
    local f="$BATS_TEST_TMPDIR/stderr"
    {
        echo 'pg_restore: error: could not execute query: ERROR:  schema "metric_helpers" does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  schema "metric_helpers" does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  schema "metric_helpers" does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  duplicate key SECRET-ROW jean.dupont@example.ch'
    } > "$f"
    restore_classify_errors "$f"
    [ "$RESTORE_ERR_TOLERATED" = "3" ]
    [ "$RESTORE_ERR_BLOCKING" = "1" ]
    [ "${RESTORE_ERR_TOLERATED_KIND_COUNTS[schema]}" = "3" ]
    run restore_tolerated_summary
    [ "$output" = "schema:3" ]
    [[ "$output" != *metric_helpers* ]]
    [[ "$output" != *SECRET-ROW* ]]
    [[ "$output" != *jean.dupont* ]]
}

@test "tolerated_summary: reports a fixed kind count without identifiers" {
    local f="$BATS_TEST_TMPDIR/stderr" i
    : > "$f"
    for i in $(seq 1 12); do
        echo "pg_restore: error: could not execute query: ERROR:  function metric_helpers.helper_${i}(boolean) does not exist" >> "$f"
    done
    restore_classify_errors "$f"
    [ "$RESTORE_ERR_TOLERATED" = "12" ]
    run restore_tolerated_summary
    [ "$output" = "function:12" ]
    [[ "$output" != *metric_helpers* ]]
    [[ "$output" != *helper_* ]]
}

@test "classify_errors: empty or missing stderr file -> all zero" {
    restore_classify_errors "$BATS_TEST_TMPDIR/does-not-exist"
    [ "$RESTORE_ERR_TOTAL" = "0" ]
    [ "$RESTORE_ERR_BLOCKING" = "0" ]
    [ "$RESTORE_ERR_TOLERATED" = "0" ]
}

@test "spilo_artifact_tolerated: kinds and qualified names" {
    spilo_artifact_tolerated extension bg_mon
    spilo_artifact_tolerated extension set_user
    spilo_artifact_tolerated schema user_management
    spilo_artifact_tolerated role admin
    spilo_artifact_tolerated function metric_helpers.get_table_bloat
    spilo_artifact_tolerated relation zalando.some_table
    ! spilo_artifact_tolerated extension postgis
    ! spilo_artifact_tolerated schema public
    ! spilo_artifact_tolerated role app_user
    ! spilo_artifact_tolerated relation public.users
    # A bare (unqualified) relation is never whitelisted by schema.
    ! spilo_artifact_tolerated relation metric_helpers
}

# ---------------------------------------------------------------------------
# Structural counts: public-schema scoping, shared by both sides
# ---------------------------------------------------------------------------

@test "structural count SQL is public-scoped and shared by both sides" {
    [[ "$PG_SQL_TRIGGER_COUNT" == *"NOT t.tgisinternal"* ]]
    [[ "$PG_SQL_TRIGGER_COUNT" == *"nspname = 'public'"* ]]
    [[ "$PG_SQL_FK_COUNT" == *"contype = 'f'"* ]]
    [[ "$PG_SQL_FK_COUNT" == *"nspname = 'public'"* ]]
    [[ "$PG_SQL_INDEX_COUNT" == *"schemaname='public'"* ]]

    # The drill must reference the shared constants, not private SQL copies.
    local root
    root=$(repo_root)
    grep -q 'PG_SQL_INDEX_COUNT' "$root/lib/restore.sh"
    grep -q 'PG_SQL_FK_COUNT' "$root/lib/restore.sh"
    grep -q 'PG_SQL_TRIGGER_COUNT' "$root/lib/restore.sh"
    ! grep -q 'FROM pg_trigger' "$root/lib/restore.sh"
    ! grep -q "contype='f'" "$root/lib/restore.sh"
}

# ---------------------------------------------------------------------------
# encrypted_format: backup-side capture (stubbed psql) and drill-side
# fidelity check (stubbed rq)
# ---------------------------------------------------------------------------

stub_chat_api_psql() {
    # Direct-runner stub: dispatch canned scalars by SQL shape. Only
    # agent_instances exists; two token columns with a mixed distribution.
    pg_psql() {
        local sql="$2"
        case "$sql" in
            *string_agg*) echo "auth_token instance_token" ;;
            *'COUNT("auth_token")'*) echo "8 8" ;;
            *'COUNT("instance_token")'*) echo "652 640" ;;
            *"to_regclass('public.agent_instances')"*) echo "t" ;;
            *to_regclass*) echo "f" ;;
            *created_at*) echo "f" ;;
            *"COUNT(*) FROM public.agent_instances"*) echo "652" ;;
            *pg_indexes*) echo "12" ;;
            *pg_constraint*) echo "3" ;;
            *pg_trigger*) echo "2" ;;
            *) echo "" ;;
        esac
    }
}

@test "pg_collect_validation: records encrypted_format for chat_api" {
    stub_chat_api_psql
    pg_collect_validation chat_api direct true
    [ "$(jq -r '.validation.encrypted_format."agent_instances.auth_token".total' <<<"$PG_COLLECT_JSON")" = "8" ]
    [ "$(jq -r '.validation.encrypted_format."agent_instances.auth_token".wellformed' <<<"$PG_COLLECT_JSON")" = "8" ]
    [ "$(jq -r '.validation.encrypted_format."agent_instances.instance_token".total' <<<"$PG_COLLECT_JSON")" = "652" ]
    [ "$(jq -r '.validation.encrypted_format."agent_instances.instance_token".wellformed' <<<"$PG_COLLECT_JSON")" = "640" ]
    # Scoped structural counts land unchanged alongside.
    [ "$(jq -r '.validation.trigger_count' <<<"$PG_COLLECT_JSON")" = "2" ]
    [ "$(jq -r '.validation.fk_count' <<<"$PG_COLLECT_JSON")" = "3" ]
}

@test "pg_collect_validation: no encrypted_format key for other databases" {
    stub_chat_api_psql
    pg_collect_validation postgres direct true
    [ "$(jq -r '.validation | has("encrypted_format")' <<<"$PG_COLLECT_JSON")" = "false" ]
}

fidelity_setup() {
    RESTORE_WORK_DIR="$BATS_TEST_TMPDIR/work"
    mkdir -p "$RESTORE_WORK_DIR"
    RESTORE_CHECKS_FILE="$BATS_TEST_TMPDIR/checks.ndjson"
    : > "$RESTORE_CHECKS_FILE"
    cat > "$RESTORE_WORK_DIR/manifest.json" <<'JSON'
{"databases": [{"name": "chat_api",
  "validation": {"encrypted_format":
    {"agent_instances.instance_token": {"total": 652, "wellformed": 640}}}}]}
JSON
}

fidelity_check_json() {
    jq -c 'select(.id == "chat_api.encrypted_columns_fidelity")' "$RESTORE_CHECKS_FILE"
}

@test "encrypted fidelity: matching distribution passes" {
    fidelity_setup
    rq() { echo "652 640"; }
    validate_encrypted_fidelity chat_api
    [ "$(fidelity_check_json | jq -r '.pass')" = "true" ]
    [ "$(fidelity_check_json | jq -r '.observed')" = \
        "encrypted_column_mismatches=0;encrypted_columns=1" ]
}

@test "encrypted fidelity: drifted wellformed count fails" {
    fidelity_setup
    rq() { echo "652 500"; }
    validate_encrypted_fidelity chat_api
    [ "$(fidelity_check_json | jq -r '.pass')" = "false" ]
    [ "$(fidelity_check_json | jq -r '.observed')" = \
        "encrypted_column_mismatches=1;encrypted_columns=1" ]
}

@test "encrypted fidelity: manifest without encrypted_format -> skipped pass" {
    fidelity_setup
    cat > "$RESTORE_WORK_DIR/manifest.json" <<'JSON'
{"databases": [{"name": "chat_api",
  "validation": {"snapshot_consistent": true, "tables": {}}}]}
JSON
    rq() { echo "652 640"; }
    validate_encrypted_fidelity chat_api
    [ "$(fidelity_check_json | jq -r '.pass')" = "true" ]
    [ "$(fidelity_check_json | jq -r '.observed')" = "legacy_manifest_skipped" ]
}

@test "encrypted fidelity: empty encrypted_format object -> pass with note" {
    fidelity_setup
    cat > "$RESTORE_WORK_DIR/manifest.json" <<'JSON'
{"databases": [{"name": "chat_api",
  "validation": {"encrypted_format": {}}}]}
JSON
    validate_encrypted_fidelity chat_api
    [ "$(fidelity_check_json | jq -r '.pass')" = "true" ]
    [ "$(fidelity_check_json | jq -r '.observed')" = \
        "encrypted_column_mismatches=0;encrypted_columns=0" ]
}

@test "durable report: encrypted fidelity retains aggregate mismatch counts only" {
    legacy_report_setup
    : > "$RESTORE_CHECKS_FILE"
    jq -n '
        {format_version: 2, backup_id: "2026-01-01T0000Z-synthetic",
         started_at: "2026-01-01T00:00:00Z", completed_at: "2026-01-01T00:05:00Z",
         databases: [{name: "chat_api", validation: {encrypted_format: {
           "OBJECT_CANARY_TABLE.OBJECT_CANARY_COLUMN": {total: 1, wellformed: 1},
           "private_table_canary.private_column_canary": {total: 2, wellformed: 2}
         }}}]}' > "$RESTORE_WORK_DIR/manifest.json"
    rq() { printf '%s\n' 'FORBIDDEN_QUERY_VALUE_CANARY'; }

    validate_encrypted_fidelity chat_api
    restore_report_write FAIL

    local report="$RESTORE_WORK_DIR/report.json" observed
    observed=$(jq -r '.checks[0].observed' "$report")
    printf 'ENCRYPTED_FIDELITY_OBSERVED=%s\n' "$observed" >&3
    [ "$observed" = "encrypted_column_mismatches=2;encrypted_columns=2" ]
    [ "$(jq -r '.checks[0].pass' "$report")" = "false" ]
    run grep -Eio 'OBJECT_CANARY|private_(table|column)_canary|FORBIDDEN_QUERY_VALUE_CANARY' "$report"
    printf 'ENCRYPTED_FIDELITY_IDENTIFIER_HITS=%s\n' "${output:-none}" >&3
    [ "$status" -eq 1 ]
}

@test "durable report: table and timestamp mismatches retain aggregate counts only" {
    legacy_report_setup
    : > "$RESTORE_CHECKS_FILE"
    jq -n '
        {format_version: 2, backup_id: "2026-01-01T0000Z-synthetic",
         started_at: "2026-01-01T00:00:00Z", completed_at: "2026-01-01T00:05:00Z",
         databases: [{name: "chat_api", validation: {
           snapshot_consistent: true, migrations: null,
           tables: {
             "private_table_canary": {count: 7, max_created_at: "2026-01-01T00:00:00Z"},
             "sensitive_table_canary": {count: 9, max_created_at: "2026-01-02T00:00:00Z"}
           }, index_count: 1, fk_count: 1, trigger_count: 1,
           encrypted_format: {}}}]}' > "$RESTORE_WORK_DIR/manifest.json"
    rq() {
        local sql="$2"
        case "$sql" in
            *"pg_extension"*) echo 1 ;;
            *"response_authors"*) echo t ;;
            *"COUNT(*) FROM public"*) echo 0 ;;
            *"MAX(created_at)"*) echo f ;;
            *"pg_indexes"* | *"pg_constraint"* | *"pg_trigger"*) echo 1 ;;
            *"pg_sequences"*) echo 0 ;;
            *) echo 0 ;;
        esac
    }

    validate_database chat_api
    restore_report_write FAIL

    local report="$RESTORE_WORK_DIR/report.json" counts timestamps
    counts=$(jq -r '.checks[] | select(.id == "chat_api.table_counts") | .observed' "$report")
    timestamps=$(jq -r '.checks[] | select(.id == "chat_api.max_created_at") | .observed' "$report")
    printf 'TABLE_COUNT_OBSERVED=%s\nTIMESTAMP_OBSERVED=%s\n' "$counts" "$timestamps" >&3
    [ "$counts" = "table_count_mismatches=2" ]
    [ "$timestamps" = "timestamp_mismatches=2" ]
    [ "$(jq -r '[.checks[] | select(.id == "chat_api.table_counts" or .id == "chat_api.max_created_at") | .pass] | all(. == false)' "$report")" = "true" ]
    run grep -Eio '(private|sensitive)_table_canary' "$report"
    printf 'TABLE_TIMESTAMP_IDENTIFIER_HITS=%s\n' "${output:-none}" >&3
    [ "$status" -eq 1 ]
}

@test "timestamp fidelity: fractional manifest precision survives safe SQL parsing" {
    legacy_report_setup
    : > "$RESTORE_CHECKS_FILE"
    jq -n '
        {format_version: 2, backup_id: "2026-01-01T0000Z-synthetic",
         started_at: "2026-01-01T00:00:00Z", completed_at: "2026-01-01T00:05:00Z",
         databases: [{name: "chat_api", validation: {
           snapshot_consistent: true,
           tables: {"fractional_timestamp_canary": {
             count: 7, max_created_at: "2026-01-01 00:00:00.123456+00"}},
           index_count: 1, fk_count: 1, trigger_count: 1,
           encrypted_format: {}}}]}' > "$RESTORE_WORK_DIR/manifest.json"
    rq() {
        local sql="$2"
        case "$sql" in
            *"pg_extension"*) echo 1 ;;
            *"response_authors"*) echo t ;;
            *"COUNT(*) FROM public"*) echo 7 ;;
            *"MAX(created_at)"*)
                [[ "$sql" == *".123456"* ]] && echo t || echo f
                ;;
            *"pg_indexes"* | *"pg_constraint"* | *"pg_trigger"*) echo 1 ;;
            *"pg_sequences"*) echo 0 ;;
            *) echo 0 ;;
        esac
    }

    validate_database chat_api

    local observed
    observed=$(jq -r 'select(.id == "chat_api.max_created_at") | .observed' "$RESTORE_CHECKS_FILE")
    printf 'FRACTIONAL_TIMESTAMP_OBSERVED=%s\n' "$observed" >&3
    [ "$observed" = "timestamp_mismatches=0" ]
    [ "$(jq -r 'select(.id == "chat_api.max_created_at") | .pass' "$RESTORE_CHECKS_FILE")" = "true" ]
}

@test "durable report: all 36 check fields and metadata reject unstructured text" {
    legacy_report_setup
    : > "$RESTORE_CHECKS_FILE"
    RESTORE_NOTES='["FORBIDDEN_NOTE_CANARY"]'
    RESTORE_ERROR_CLASSES='{"FORBIDDEN_SCOPE_CANARY":"FORBIDDEN_RAW_TEXT_CANARY"}'
    RESTORE_SIZES='{"FORBIDDEN_OBJECT_CANARY":{"plaintext_bytes":1,"ciphertext_bytes":2}}'

    local id verdict report
    while IFS= read -r id; do
        check_add "$id" "FORBIDDEN_EXPECTED_CANARY" "FORBIDDEN_OBSERVED_CANARY" true
    done < "$(repo_root)/tests/fixtures/restore-check-ids.txt"
    verdict=$(restore_verdict)
    restore_report_write "$verdict"
    report="$RESTORE_WORK_DIR/report.json"

    printf 'UNSTRUCTURED_CHECK_VERDICT=%s\n' "$verdict" >&3
    [ "$verdict" = "FAIL" ]
    [ "$(jq -r '[.checks[] | .expected == "contract_valid" and .observed == "contract_violation" and (.pass == false)] | all' "$report")" = "true" ]
    [ "$(jq -c '.notes' "$report")" = '[]' ]
    [ "$(jq -c '.error_classes' "$report")" = '{}' ]
    [ "$(jq -c '.sizes' "$report")" = '{}' ]
    run grep -Eo 'FORBIDDEN_[A-Z_]+' "$report"
    printf 'FULL_REPORT_UNSTRUCTURED_HITS=%s\n' "${output:-none}" >&3
    [ "$status" -eq 1 ]
}

@test "durable report: all canonical and generic checks reject semantic contradictions" {
    legacy_report_setup
    : > "$RESTORE_CHECKS_FILE"
    local matrix="$BATS_TEST_TMPDIR/semantic-contradictions.tsv"
    cat > "$matrix" <<'EOF'
cluster.manifest_complete	manifest_complete	download_failed
cluster.ciphertext_sha256	checksum_mismatches=0	checksum_mismatches=9;objects=9
cluster.plaintext_sha256	decrypt_failures=0;checksum_mismatches=0	key_unavailable
cluster.pg_major	major=16	major=15
cluster.globals_errors	non_benign_errors=0	non_benign_errors=1
cluster.app_role_connectivity	login=ok	login=failed
cloud_api.restore_errors	blocking_errors=0	blocking_errors=1;total_errors=1;tolerated_errors=0;return_code=1
chat_api.restore_errors	blocking_errors=0	blocking_errors=1;total_errors=1;tolerated_errors=0;return_code=1
cluster.databases_match	missing_databases=0	missing_databases=1;expected_databases=3
cluster.roles	login_roles=2	login_roles=1
cloud_api.migration_version	target=63;floor=63	value=62
cloud_api.migration_row_count	target=62;floor=62	value=61
cloud_api.ownership	owner=postgres	owner=unexpected
cloud_api.uuid_ossp	extension=present	extension=absent
cloud_api.rename_sentinels	sentinels_present=2	sentinels_present=1
cloud_api.table_counts	table_count_mismatches=0	table_count_mismatches=1
cloud_api.max_created_at	timestamp_mismatches=0	timestamp_mismatches=1
cloud_api.index_count	count=5	count=4
cloud_api.fk_count	count=5	count=4
cloud_api.trigger_count	count=5	count=4
cloud_api.sequences	reset_sequences=0	reset_sequences=1
chat_api.migration_version	target=34;floor=34	value=33
chat_api.migration_row_count	target=33;floor=33	value=32
chat_api.ownership	owner=postgres	owner=missing
chat_api.uuid_ossp	extension=present	extension=absent
chat_api.response_authors_absent	table=absent	table=present
chat_api.table_counts	table_count_mismatches=0	table_count_mismatches=1
chat_api.max_created_at	timestamp_mismatches=0	timestamp_mismatches=1
chat_api.index_count	count=5	count=4
chat_api.fk_count	count=5	count=4
chat_api.trigger_count	count=5	count=4
chat_api.sequences	reset_sequences=0	reset_sequences=1
chat_api.encrypted_columns_fidelity	encrypted_column_mismatches=0	encrypted_column_mismatches=1;encrypted_columns=1
cluster.rpo_freshness	age_seconds<86400	age_seconds=86400
bucket.drift	drifted_settings=0	drifted_settings=1
cluster.rto_within_target	total_seconds<14400	total_seconds=14400
rag_service.restore_errors	blocking_errors=0	blocking_errors=1;total_errors=1;tolerated_errors=0;return_code=1
rag_service.index_count	count=5	count=4
rag_service.fk_count	count=5	count=4
rag_service.trigger_count	count=5	count=4
rag_service.sequences	reset_sequences=0	reset_sequences=1
database_000003.restore_errors	blocking_errors=0	blocking_errors=1;total_errors=1;tolerated_errors=0;return_code=1
database_000003.index_count	count=5	count=4
database_000003.fk_count	count=5	count=4
database_000003.trigger_count	count=5	count=4
database_000003.sequences	reset_sequences=0	reset_sequences=1
EOF

    head -n 36 "$matrix" | cut -f1 > "$BATS_TEST_TMPDIR/canonical-semantic-ids.txt"
    cmp "$BATS_TEST_TMPDIR/canonical-semantic-ids.txt" \
        "$(repo_root)/tests/fixtures/restore-check-ids.txt"

    local id expected observed verdict report accepted canonical_accepted generic_accepted
    while IFS=$'\t' read -r id expected observed; do
        check_add "$id" "$expected" "$observed" true
    done < "$matrix"
    verdict=$(restore_verdict)
    restore_report_write "$verdict"
    report="$RESTORE_WORK_DIR/report.json"
    accepted=$(jq '[.checks[] | select(.pass == true)] | length' "$report")
    canonical_accepted=$(jq '[.checks[0:36][] | select(.pass == true)] | length' "$report")
    generic_accepted=$(jq '[.checks[36:][] | select(.pass == true)] | length' "$report")

    printf 'SEMANTIC_CONTRADICTIONS=46\nCANONICAL_CONTRADICTIONS_ACCEPTED=%s\nGENERIC_CONTRADICTIONS_ACCEPTED=%s\nSEMANTIC_CONTRADICTION_VERDICT=%s\n' \
        "$canonical_accepted" "$generic_accepted" "$verdict" >&3
    [ "$(jq '.checks | length' "$report")" -eq 46 ]
    [ "$accepted" -eq 0 ]
    [ "$canonical_accepted" -eq 0 ]
    [ "$generic_accepted" -eq 0 ]
    [ "$verdict" = "FAIL" ]
    [ "$(jq -r '[.checks[] | .expected == "contract_valid" and .observed == "contract_violation" and (.pass == false)] | all' "$report")" = "true" ]
}

@test "durable report: bounded numeric pass coupling uses decimal values" {
    legacy_report_setup
    : > "$RESTORE_CHECKS_FILE"

    check_add cluster.globals_errors non_benign_errors=0 non_benign_errors=000 true
    check_add cluster.roles login_roles=2 login_roles=02 true
    check_add cloud_api.table_counts table_count_mismatches=0 table_count_mismatches=0000 true
    check_add chat_api.max_created_at timestamp_mismatches=0 timestamp_mismatches=0000 true
    check_add database_000003.sequences reset_sequences=0 reset_sequences=000 true

    local verdict report
    verdict=$(restore_verdict)
    restore_report_write "$verdict"
    report="$RESTORE_WORK_DIR/report.json"
    printf 'DECIMAL_COUPLING_PASSES=%s\nDECIMAL_COUPLING_VERDICT=%s\n' \
        "$(jq '[.checks[] | select(.pass == true)] | length' "$report")" "$verdict" >&3
    [ "$(jq '.checks | length' "$report")" -eq 5 ]
    [ "$(jq -r '[.checks[] | .pass] | all' "$report")" = "true" ]
    [ "$verdict" = "PASS" ]
}

@test "durable report: all canonical and generic checks reject false success claims" {
    legacy_report_setup
    : > "$RESTORE_CHECKS_FILE"
    local matrix="$BATS_TEST_TMPDIR/semantic-successes.tsv"
    cat > "$matrix" <<'EOF'
cluster.manifest_complete	manifest_complete	objects_present=3
cluster.ciphertext_sha256	checksum_mismatches=0	checksum_mismatches=0;objects=3
cluster.plaintext_sha256	decrypt_failures=0;checksum_mismatches=0	decrypt_failures=0;checksum_mismatches=0;objects=3
cluster.pg_major	major=16	major=16
cluster.globals_errors	non_benign_errors=0	non_benign_errors=0
cluster.app_role_connectivity	login=ok	login=ok
cloud_api.restore_errors	blocking_errors=0	blocking_errors=0;total_errors=0;tolerated_errors=0;return_code=0
chat_api.restore_errors	blocking_errors=0	blocking_errors=0;total_errors=0;tolerated_errors=0;return_code=0
cluster.databases_match	missing_databases=0	missing_databases=0;expected_databases=3
cluster.roles	login_roles=2	login_roles=2
cloud_api.migration_version	target=63;floor=63	value=63
cloud_api.migration_row_count	target=62;floor=62	value=62
cloud_api.ownership	owner=postgres	owner=postgres
cloud_api.uuid_ossp	extension=present	extension=present
cloud_api.rename_sentinels	sentinels_present=2	sentinels_present=2
cloud_api.table_counts	table_count_mismatches=0	table_count_mismatches=0
cloud_api.max_created_at	timestamp_mismatches=0	timestamp_mismatches=0
cloud_api.index_count	count=5	count=5
cloud_api.fk_count	count=5	count=5
cloud_api.trigger_count	count=5	count=5
cloud_api.sequences	reset_sequences=0	reset_sequences=0
chat_api.migration_version	target=34;floor=34	value=34
chat_api.migration_row_count	target=33;floor=33	value=33
chat_api.ownership	owner=postgres	owner=postgres
chat_api.uuid_ossp	extension=present	extension=present
chat_api.response_authors_absent	table=absent	table=absent
chat_api.table_counts	table_count_mismatches=0	table_count_mismatches=0
chat_api.max_created_at	timestamp_mismatches=0	timestamp_mismatches=0
chat_api.index_count	count=5	count=5
chat_api.fk_count	count=5	count=5
chat_api.trigger_count	count=5	count=5
chat_api.sequences	reset_sequences=0	reset_sequences=0
chat_api.encrypted_columns_fidelity	encrypted_column_mismatches=0	encrypted_column_mismatches=0;encrypted_columns=1
cluster.rpo_freshness	age_seconds<86400	age_seconds=60
bucket.drift	drifted_settings=0	drifted_settings=0
cluster.rto_within_target	total_seconds<14400	total_seconds=300
rag_service.restore_errors	blocking_errors=0	blocking_errors=0;total_errors=2;tolerated_errors=2;return_code=1
rag_service.index_count	count=5	count=5
rag_service.fk_count	count=5	count=5
rag_service.trigger_count	count=5	count=5
rag_service.sequences	reset_sequences=0	reset_sequences=0
database_000003.restore_errors	blocking_errors=0	blocking_errors=0;total_errors=0;tolerated_errors=0;return_code=0
database_000003.index_count	count=5	count=5
database_000003.fk_count	count=5	count=5
database_000003.trigger_count	count=5	count=5
database_000003.sequences	reset_sequences=0	reset_sequences=0
EOF

    head -n 36 "$matrix" | cut -f1 > "$BATS_TEST_TMPDIR/canonical-success-ids.txt"
    cmp "$BATS_TEST_TMPDIR/canonical-success-ids.txt" \
        "$(repo_root)/tests/fixtures/restore-check-ids.txt"

    local id expected observed verdict report
    while IFS=$'\t' read -r id expected observed; do
        check_add "$id" "$expected" "$observed" false
    done < "$matrix"
    verdict=$(restore_verdict)
    restore_report_write "$verdict"
    report="$RESTORE_WORK_DIR/report.json"

    printf 'FALSE_SUCCESS_CLAIMS=46\nFALSE_SUCCESS_CLAIMS_PERSISTED=0\nFALSE_SUCCESS_VERDICT=%s\n' \
        "$verdict" >&3
    [ "$(jq '.checks | length' "$report")" -eq 46 ]
    [ "$(jq -r '[.checks[] | .expected == "contract_valid" and .observed == "contract_violation" and (.pass == false)] | all' "$report")" = "true" ]
    [ "$verdict" = "FAIL" ]
}

@test "check contract validates shape before semantic coupling" {
    local trace="$BATS_TEST_TMPDIR/contract-order"
    : > "$trace"
    restore_check_shape_valid() {
        echo shape >> "$trace"
        return 1
    }
    restore_check_semantics_valid() {
        echo semantic >> "$trace"
        return 0
    }
    if restore_check_contract_valid cluster.ciphertext_sha256 \
        checksum_mismatches=0 'checksum_mismatches=0;objects=1' true; then
        false
    fi
    [ "$(cat "$trace")" = "shape" ]

    : > "$trace"
    restore_check_shape_valid() {
        echo shape >> "$trace"
        return 0
    }
    restore_check_contract_valid cluster.ciphertext_sha256 \
        checksum_mismatches=0 'checksum_mismatches=0;objects=1' true
    [ "$(tr '\n' ' ' < "$trace")" = "shape semantic " ]
}

@test "database scopes: unknown names become distinct stable ordinals" {
    legacy_report_setup
    : > "$RESTORE_CHECKS_FILE"
    RESTORE_DBS=(postgres chat_api private_customer_db secret_reporting_db)
    local first second report verdict first_name_hash second_name_hash
    first=$(db_prefix private_customer_db)
    second=$(db_prefix secret_reporting_db)
    [ "$first" = "database_000003" ]
    [ "$second" = "database_000004" ]
    [ "$(db_prefix private_customer_db)" = "$first" ]
    [ "$first" != "$second" ]
    first_name_hash=$(printf %s private_customer_db | sha256sum | awk '{print $1}')
    second_name_hash=$(printf %s secret_reporting_db | sha256sum | awk '{print $1}')
    [[ "$first$second" != *private_customer_db* ]]
    [[ "$first$second" != *secret_reporting_db* ]]
    [[ "$first$second" != *sha256* ]]
    restore_check_id_known "${first}.restore_errors"
    restore_check_id_known "${second}.sequences"

    check_add "${first}.restore_errors" "blocking_errors=0" \
        "blocking_errors=0;total_errors=0;tolerated_errors=0;return_code=0" true
    check_add "${second}.restore_errors" "blocking_errors=0" \
        "blocking_errors=1;total_errors=1;tolerated_errors=0;return_code=1" false
    verdict=$(restore_verdict)
    restore_report_write "$verdict"
    report="$RESTORE_WORK_DIR/report.json"

    [ "$verdict" = "FAIL" ]
    [ "$(jq -r '.checks[0].id' "$report")" = "database_000003.restore_errors" ]
    [ "$(jq -r '.checks[0].pass' "$report")" = "true" ]
    [ "$(jq -r '.checks[1].id' "$report")" = "database_000004.restore_errors" ]
    [ "$(jq -r '.checks[1].observed' "$report")" = \
        "blocking_errors=1;total_errors=1;tolerated_errors=0;return_code=1" ]
    [ "$(jq -r '.checks[1].pass' "$report")" = "false" ]
    run grep -E "private_customer_db|secret_reporting_db|${first_name_hash}|${second_name_hash}" "$report"
    printf 'ORDINAL_REPORT_IDENTIFIER_HITS=%s\n' "${output:-none}" >&3
    [ "$status" -eq 1 ]
}


@test "classify_errors: blocking summary retains fixed kinds and counts only" {
    local f="$BATS_TEST_TMPDIR/stderr"
    {
        echo 'pg_restore: error: could not execute query: ERROR:  extension "nonexistent_ext" does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  schema "customschema" does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  duplicate key value violates unique constraint "users_pkey"'
        echo 'DETAIL:  Key (id)=(42) already exists.'
    } > "$f"
    restore_classify_errors "$f"
    [ "$RESTORE_ERR_BLOCKING" = "3" ]
    [ "$RESTORE_ERR_BLOCKING_UNCLASSIFIED" = "1" ]
    summary=$(restore_blocking_summary)
    [ "$summary" = "extension:1, schema:1, unclassified:1" ]
    [[ "$summary" != *nonexistent_ext* ]]
    [[ "$summary" != *customschema* ]]
    [[ "$summary" != *"users_pkey"* ]]
    [[ "$summary" != *"Key (id)"* ]]
}

@test "durable report: classifier pipeline retains only fixed kinds and counts" {
    legacy_report_setup
    : > "$RESTORE_CHECKS_FILE"

    local stderr_file="$RESTORE_STDERR_DIR/restore-canary.stderr"
    printf '%s\n' \
        'pg_restore: error: could not execute query: ERROR:  extension "FORBIDDEN_EXTENSION_CANARY" does not exist' \
        'pg_restore: error: could not execute query: ERROR:  schema "FORBIDDEN_SCHEMA_CANARY" does not exist' \
        'pg_restore: error: could not execute query: ERROR:  relation "FORBIDDEN_SCHEMA_CANARY.FORBIDDEN_RELATION_CANARY" does not exist' \
        'pg_restore: error: could not execute query: ERROR:  function FORBIDDEN_SCHEMA_CANARY.FORBIDDEN_FUNCTION_CANARY(integer) does not exist' \
        'pg_restore: error: duplicate key password=FORBIDDEN_PASSWORD_CANARY' \
        'CONTEXT: COPY FORBIDDEN_COPY_CANARY, line 7: "FORBIDDEN_ROW_CANARY"' \
        'STATEMENT: SELECT FORBIDDEN_COLUMN_CANARY FROM FORBIDDEN_SCHEMA_CANARY.FORBIDDEN_RELATION_CANARY' \
        > "$stderr_file"

    restore_classify_errors "$stderr_file"
    local summary observed report durable_observed
    summary=$(stderr_summarize "$stderr_file")
    error_class_add synthetic_restore "$summary"
    observed="blocking_errors=${RESTORE_ERR_BLOCKING};total_errors=${RESTORE_ERR_TOTAL};tolerated_errors=${RESTORE_ERR_TOLERATED};return_code=1"
    check_add "cloud_api.restore_errors" "blocking_errors=0" "$observed" false
    restore_report_write FAIL

    report="$RESTORE_WORK_DIR/report.json"
    durable_observed=$(jq -r '.checks[] | select(.id == "cloud_api.restore_errors") | .observed' "$report")
    printf 'CLASSIFIER_DURABLE_OBSERVED=%s\n' "$durable_observed" >&3
    run grep -Eo 'FORBIDDEN_[A-Z_]+' "$report"
    printf 'CLASSIFIER_FULL_REPORT_FORBIDDEN_HITS=%s\n' "${output:-none}" >&3
    [ "$status" -eq 1 ]
    [ "$durable_observed" = \
        'blocking_errors=5;total_errors=5;tolerated_errors=0;return_code=1' ]
    [ "$(jq -r '.verdict' "$report")" = "FAIL" ]
    [ "$(jq -r '.checks[0].pass' "$report")" = "false" ]
}

@test "durable report: checksum and decrypt failures never retain object or key paths" {
    legacy_report_setup
    : > "$RESTORE_CHECKS_FILE"
    mkdir -p "$RESTORE_WORK_DIR/enc" "$RESTORE_WORK_DIR/plain"
    jq -n \
        '{format_version: 2, restore_profile: "legacy-v1",
          backup_id: "2026-01-01T0000Z-synthetic",
          started_at: "2026-01-01T00:00:00Z",
          completed_at: "2026-01-01T00:05:00Z",
          globals: {object: "FORBIDDEN_CIPHER_OBJECT_CANARY.enc",
                    sha256_ciphertext: "0000", sha256_plaintext: "1111"},
          databases: [{name: "postgres", object: "FORBIDDEN_DECRYPT_OBJECT_CANARY.enc",
                       sha256_ciphertext: "2222", sha256_plaintext: "3333"}],
          encryption: {key_path: "/forbidden/key/FORBIDDEN_KEY_PATH_CANARY"}}' \
        > "$RESTORE_WORK_DIR/manifest.json"
    printf 'ciphertext-one' > "$RESTORE_WORK_DIR/enc/FORBIDDEN_CIPHER_OBJECT_CANARY.enc"
    printf 'ciphertext-two' > "$RESTORE_WORK_DIR/enc/FORBIDDEN_DECRYPT_OBJECT_CANARY.enc"

    restore_verify_ciphertext || true
    fetch_encryption_key() { return 1; }
    restore_decrypt || true
    fetch_encryption_key() { return 0; }
    openssl() {
        printf '%s\n' 'bad decrypt FORBIDDEN_DECRYPT_STDERR_CANARY /forbidden/decrypt/path' >&2
        return 1
    }
    restore_decrypt || true
    restore_report_write FAIL

    local report="$RESTORE_WORK_DIR/report.json" observations
    observations=$(jq -c '[.checks[] | {id, observed}]' "$report")
    printf 'CHECKSUM_DECRYPT_DURABLE_OBSERVED=%s\n' "$observations" >&3
    run grep -Eo 'FORBIDDEN_[A-Z_]+|/forbidden/[^" ]+' "$report"
    printf 'CHECKSUM_DECRYPT_FULL_REPORT_FORBIDDEN_HITS=%s\n' "${output:-none}" >&3
    [ "$status" -eq 1 ]
    [ "$(jq -c '[.checks[].observed]' "$report")" = \
        '["checksum_mismatches=2;objects=2","key_unavailable","decrypt_failures=2;checksum_mismatches=0;objects=2"]' ]
}

@test "classify_errors: drill-attempt-10 blocking set is tolerated" {
    local f="$BATS_TEST_TMPDIR/stderr"
    {
        echo 'pg_restore: error: could not execute query: ERROR:  extension "plpython3u" does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  language "plpython3u" does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  schema "cron" does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  relation "cron.jobid_seq" does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  function zmon_utils.get_database_cluster_system_information() does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  function public.set_user(text) does not exist'
        echo 'pg_restore: error: could not execute query: ERROR:  relation "public.pg_auth_mon" does not exist'
    } > "$f"
    restore_classify_errors "$f"
    [ "$RESTORE_ERR_TOTAL" = "7" ]
    [ "$RESTORE_ERR_TOLERATED" = "7" ]
    [ "$RESTORE_ERR_BLOCKING" = "0" ]
}
