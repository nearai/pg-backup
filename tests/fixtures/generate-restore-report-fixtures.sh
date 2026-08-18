#!/usr/bin/env bash
# Deterministically generate the canonical sanitized restore reports through
# the production report function. No database, network, or backup object is used.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUTPUT_DIR="${FIXTURE_OUTPUT_DIR:-$ROOT/tests/fixtures}"
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT
mkdir -p "$OUTPUT_DIR"

# shellcheck disable=SC1091
source "$ROOT/entrypoint.sh"
# shellcheck disable=SC1091
source "$ROOT/lib/restore.sh"

FIXTURE_NOW="2026-01-01T00:15:00Z"
FIXTURE_NOW_EPOCH=1767226500
date() {
    if [[ "${1:-}" == "-u" && "${2:-}" == "+%FT%TZ" ]]; then
        echo "$FIXTURE_NOW"
    elif [[ "${1:-}" == "+%s" ]]; then
        echo "$FIXTURE_NOW_EPOCH"
    else
        command date "$@"
    fi
}

add_passing_check() {
    local id="$1"
    case "$id" in
        cluster.manifest_complete) check_add "$id" manifest_complete objects_present=3 true ;;
        cluster.ciphertext_sha256) check_add "$id" checksum_mismatches=0 'checksum_mismatches=0;objects=3' true ;;
        cluster.plaintext_sha256) check_add "$id" 'decrypt_failures=0;checksum_mismatches=0' 'decrypt_failures=0;checksum_mismatches=0;objects=3' true ;;
        cluster.pg_major) check_add "$id" major=16 major=16 true ;;
        cluster.globals_errors) check_add "$id" non_benign_errors=0 non_benign_errors=0 true ;;
        cluster.app_role_connectivity) check_add "$id" login=ok login=ok true ;;
        cloud_api.restore_errors | chat_api.restore_errors)
            check_add "$id" blocking_errors=0 'blocking_errors=0;total_errors=0;tolerated_errors=0;return_code=0' true
            ;;
        cluster.databases_match) check_add "$id" missing_databases=0 'missing_databases=0;expected_databases=2' true ;;
        cluster.roles) check_add "$id" login_roles=2 login_roles=2 true ;;
        cloud_api.migration_version) check_add "$id" 'target=63;floor=63' value=63 true ;;
        cloud_api.migration_row_count) check_add "$id" 'target=62;floor=62' value=62 true ;;
        chat_api.migration_version) check_add "$id" 'target=34;floor=34' value=34 true ;;
        chat_api.migration_row_count) check_add "$id" 'target=33;floor=33' value=33 true ;;
        cloud_api.ownership | chat_api.ownership) check_add "$id" owner=postgres owner=postgres true ;;
        cloud_api.uuid_ossp | chat_api.uuid_ossp) check_add "$id" extension=present extension=present true ;;
        cloud_api.rename_sentinels) check_add "$id" sentinels_present=2 sentinels_present=2 true ;;
        chat_api.response_authors_absent) check_add "$id" table=absent table=absent true ;;
        cloud_api.table_counts | chat_api.table_counts) check_add "$id" table_count_mismatches=0 table_count_mismatches=0 true ;;
        cloud_api.max_created_at | chat_api.max_created_at) check_add "$id" timestamp_mismatches=0 timestamp_mismatches=0 true ;;
        cloud_api.index_count | chat_api.index_count) check_add "$id" count=2 count=2 true ;;
        cloud_api.fk_count | chat_api.fk_count) check_add "$id" count=1 count=1 true ;;
        cloud_api.trigger_count | chat_api.trigger_count) check_add "$id" count=1 count=1 true ;;
        cloud_api.sequences | chat_api.sequences) check_add "$id" reset_sequences=0 reset_sequences=0 true ;;
        chat_api.encrypted_columns_fidelity)
            check_add "$id" encrypted_column_mismatches=0 \
                'encrypted_column_mismatches=0;encrypted_columns=1' true
            ;;
        cluster.rpo_freshness) check_add "$id" 'age_seconds<86400' age_seconds=60 true ;;
        bucket.drift) check_add "$id" drifted_settings=0 drifted_settings=0 true ;;
        cluster.rto_within_target) check_add "$id" 'total_seconds<14400' total_seconds=300 true ;;
        *) return 1 ;;
    esac
}

write_fixture() {
    local verdict="$1" output_name="$2"
    RESTORE_WORK_DIR="$WORK_DIR/$verdict"
    RESTORE_STDERR_DIR="$RESTORE_WORK_DIR/stderr"
    RESTORE_CHECKS_FILE="$RESTORE_WORK_DIR/checks.ndjson"
    RESTORE_PHASES_FILE="$RESTORE_WORK_DIR/phases"
    mkdir -p "$RESTORE_STDERR_DIR"
    : > "$RESTORE_CHECKS_FILE"
    printf '%s\n' 'download 60' 'restore 180' 'validate 60' > "$RESTORE_PHASES_FILE"
    RESTORE_STARTED_AT="2026-01-01T00:10:00Z"
    DRILL_ID="synthetic-${verdict,,}"
    RESTORE_START_EPOCH=1767226200
    RESTORE_MANIFEST_KEY="backups/synthetic/manifest.json"
    RESTORE_RPO_TARGET_SECONDS=86400
    RESTORE_RTO_TARGET_SECONDS=14400
    RESTORE_DATA_AGE_SECONDS=60
    RESTORE_ERROR_CLASSES='{}'
    RESTORE_SIZES='{}'
    RESTORE_NOTES=$(jq -cn --arg note "$RESTORE_NOTE_APP_ROLE" '[$note]')
    RESTORE_PROFILE="$RESTORE_PROFILE_LEGACY"
    RESTORE_POSTMASTER_START_PRE=1767225000
    RESTORE_POSTMASTER_START_POST=1767225000
    RESTORE_SCRATCH_DISK_USED_PERCENT=42
    jq -n '{format_version: 2, restore_profile: "legacy-v1",
            backup_id: "2026-01-01T0000Z-synthetic",
            started_at: "2026-01-01T00:00:00Z",
            completed_at: "2026-01-01T00:05:00Z",
            databases: [{name: "chat_api", validation: {encrypted_format: {
              "agent_instances.instance_token": {total: 2, wellformed: 2}
            }}}]}' \
        > "$RESTORE_WORK_DIR/manifest.json"

    if [[ "$verdict" == "FAIL" ]]; then
        RESTORE_POSTMASTER_START_PRE=""
        RESTORE_SCRATCH_DISK_USED_PERCENT=90
        printf '%s\n' \
            'server closed the connection unexpectedly' \
            'No space left on device' \
            'could not extend file: No space left on device' \
            'out of memory' \
            'Cannot allocate memory' \
            'Resource temporarily unavailable' \
            'pg_restore: error: could not execute query: ERROR:  schema "FORBIDDEN_CANONICAL_SCHEMA_CANARY" does not exist' \
            > "$RESTORE_STDERR_DIR/restore.stderr"
    fi

    rq() {
        if [[ "$verdict" == "FAIL" ]]; then
            echo "2 1"
        else
            echo "2 2"
        fi
    }

    local id
    while IFS= read -r id; do
        if [[ "$verdict" == "FAIL" && "$id" == "chat_api.encrypted_columns_fidelity" ]]; then
            validate_encrypted_fidelity chat_api
        else
            add_passing_check "$id"
        fi
    done < "$ROOT/tests/fixtures/restore-check-ids.txt"

    restore_report_write "$verdict"
    jq -S . "$RESTORE_WORK_DIR/report.json" > "$OUTPUT_DIR/$output_name"
}

write_fixture PASS restore-report-pass.json
write_fixture FAIL restore-report-fail.json
