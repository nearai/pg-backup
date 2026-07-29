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

@test "classify_errors: tolerated ids deduped, no raw stderr content leaked" {
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
    [ "$RESTORE_ERR_TOLERATED_IDS" = "schema metric_helpers" ]
    run restore_tolerated_summary
    [ "$output" = "schema metric_helpers" ]
    [[ "$RESTORE_ERR_TOLERATED_IDS" != *SECRET-ROW* ]]
    [[ "$RESTORE_ERR_TOLERATED_IDS" != *jean.dupont* ]]
}

@test "tolerated_summary: caps the identifier list at 10 with +N more" {
    local f="$BATS_TEST_TMPDIR/stderr" i
    : > "$f"
    for i in $(seq 1 12); do
        echo "pg_restore: error: could not execute query: ERROR:  function metric_helpers.helper_${i}(boolean) does not exist" >> "$f"
    done
    restore_classify_errors "$f"
    [ "$RESTORE_ERR_TOLERATED" = "12" ]
    run restore_tolerated_summary
    [[ "$output" == *"function metric_helpers.helper_1,"* ]]
    [[ "$output" == *"+2 more" ]]
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
    [[ "$(fidelity_check_json | jq -r '.observed')" == *"distribution matches"* ]]
}

@test "encrypted fidelity: drifted wellformed count fails" {
    fidelity_setup
    rq() { echo "652 500"; }
    validate_encrypted_fidelity chat_api
    [ "$(fidelity_check_json | jq -r '.pass')" = "false" ]
    [[ "$(fidelity_check_json | jq -r '.observed')" == *"wellformed=500/640"* ]]
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
    [[ "$(fidelity_check_json | jq -r '.observed')" == *"predates encrypted_format capture"* ]]
}

@test "encrypted fidelity: empty encrypted_format object -> pass with note" {
    fidelity_setup
    cat > "$RESTORE_WORK_DIR/manifest.json" <<'JSON'
{"databases": [{"name": "chat_api",
  "validation": {"encrypted_format": {}}}]}
JSON
    validate_encrypted_fidelity chat_api
    [ "$(fidelity_check_json | jq -r '.pass')" = "true" ]
    [[ "$(fidelity_check_json | jq -r '.observed')" == *"no encrypted columns recorded"* ]]
}
