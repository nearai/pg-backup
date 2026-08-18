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

RESTORE_DIAGNOSTIC_LINE_LIMIT=20000
RESTORE_SCRATCH_DISK_PRESSURE_PERCENT=90
RESTORE_CHECKS_FILE=""
RESTORE_PHASES_FILE=""
RESTORE_ERROR_CLASSES="{}"
RESTORE_SIZES="{}"
RESTORE_NOTES='["prod app-role password is underivable outside prod by design; connectivity verified via ALTER ROLE + fresh SCRAM login"]'
RESTORE_REPORT_UPLOADED=0
RESTORE_STARTED_AT=""
RESTORE_PROFILE="${RESTORE_PROFILE_LEGACY:-legacy-v1}"
RESTORE_POSTMASTER_START_PRE=""
RESTORE_POSTMASTER_START_POST=""
RESTORE_SCRATCH_DISK_USED_PERCENT=""
RESTORE_FAILURE_CATEGORY=""
DRILL_PGPASSWORD=""

RESTORE_NOTE_APP_ROLE='prod app-role password is underivable outside prod by design; connectivity verified via ALTER ROLE + fresh SCRAM login'
RESTORE_NOTE_UNEXPECTED_EXIT='driver exited unexpectedly before completing the battery'

# ---------------------------------------------------------------------------
# Report plumbing
# ---------------------------------------------------------------------------

restore_check_id_known() {
    case "$1" in
        cluster.manifest_complete | cluster.ciphertext_sha256 | \
        cluster.plaintext_sha256 | cluster.pg_major | cluster.globals_errors | \
        cluster.app_role_connectivity | cluster.databases_match | cluster.roles | \
        cluster.rpo_freshness | cluster.rto_within_target | bucket.drift | \
        cloud_api.restore_errors | cloud_api.migration_version | \
        cloud_api.migration_row_count | cloud_api.ownership | cloud_api.uuid_ossp | \
        cloud_api.rename_sentinels | cloud_api.table_counts | \
        cloud_api.max_created_at | cloud_api.index_count | cloud_api.fk_count | \
        cloud_api.trigger_count | cloud_api.sequences | \
        chat_api.restore_errors | chat_api.migration_version | \
        chat_api.migration_row_count | chat_api.ownership | chat_api.uuid_ossp | \
        chat_api.response_authors_absent | chat_api.table_counts | \
        chat_api.max_created_at | chat_api.index_count | chat_api.fk_count | \
        chat_api.trigger_count | chat_api.sequences | \
        chat_api.encrypted_columns_fidelity | \
        rag_service.restore_errors | rag_service.index_count | rag_service.fk_count | \
        rag_service.trigger_count | rag_service.sequences)
            return 0
            ;;
    esac
    [[ "$1" =~ ^database_[0-9]{6}\.(restore_errors|index_count|fk_count|trigger_count|sequences)$ ]]
}

restore_database_scope_known() {
    [[ "$1" == "cloud_api" || "$1" == "chat_api" || "$1" == "rag_service" \
        || "$1" =~ ^database_[0-9]{6}$ ]]
}

restore_field_matches() {
    [[ "$1" =~ $2 ]]
}

# Every durable check field is an ID-specific fixed enum or bounded numeric
# grammar. Source identifiers and raw command text never satisfy this boundary.
restore_check_shape_valid() {
    local id="$1" expected="$2" observed="$3" pass="$4"
    [[ "$pass" == "true" || "$pass" == "false" ]] || return 1
    if [[ "$expected" == "contract_valid" && "$observed" == "contract_violation" ]]; then
        [[ "$pass" == "false" ]]
        return
    fi

    case "$id" in
        cluster.manifest_complete)
            [[ "$expected" == "manifest_complete" ]] \
                && restore_field_matches "$observed" '^(download_failed|manifest_invalid|restore_profile_unsupported|globals_object_missing|database_object_missing|objects_present=[0-9]{1,4})$'
            ;;
        cluster.ciphertext_sha256)
            [[ "$expected" == "checksum_mismatches=0" ]] \
                && restore_field_matches "$observed" '^checksum_mismatches=[0-9]{1,15};objects=[0-9]{1,15}$'
            ;;
        cluster.plaintext_sha256)
            [[ "$expected" == "decrypt_failures=0;checksum_mismatches=0" ]] \
                && restore_field_matches "$observed" '^(key_unavailable|decrypt_failures=[0-9]{1,15};checksum_mismatches=[0-9]{1,15};objects=[0-9]{1,15})$'
            ;;
        cluster.pg_major)
            restore_field_matches "$expected" '^major=([0-9]{1,3}|unknown)$' \
                && restore_field_matches "$observed" '^major=([0-9]{1,3}|unknown)$'
            ;;
        cluster.globals_errors)
            [[ "$expected" == "non_benign_errors=0" ]] \
                && restore_field_matches "$observed" '^(decompress_failed|non_benign_errors=[0-9]{1,15})$'
            ;;
        cluster.app_role_connectivity)
            [[ "$expected" == "login=ok" ]] \
                && restore_field_matches "$observed" '^login=(ok|failed)$'
            ;;
        cloud_api.restore_errors | chat_api.restore_errors | rag_service.restore_errors | \
        database_*.restore_errors)
            [[ "$expected" == "blocking_errors=0" ]] \
                && restore_field_matches "$observed" '^(database_drop_failed|blocking_errors=[0-9]{1,15};total_errors=[0-9]{1,15};tolerated_errors=[0-9]{1,15};return_code=[0-9]{1,3})$'
            ;;
        cluster.databases_match)
            [[ "$expected" == "missing_databases=0" ]] \
                && restore_field_matches "$observed" '^missing_databases=[0-9]{1,4};expected_databases=[0-9]{1,4}$'
            ;;
        cluster.roles)
            [[ "$expected" == "login_roles=2" ]] \
                && restore_field_matches "$observed" '^login_roles=([0-9]{1,2}|unknown)$'
            ;;
        cloud_api.migration_version | chat_api.migration_version)
            restore_field_matches "$expected" '^target=[0-9]{1,15};floor=[0-9]{1,15}$' \
                && restore_field_matches "$observed" '^value=([0-9]{1,15}|unknown)$'
            ;;
        cloud_api.migration_row_count | chat_api.migration_row_count)
            restore_field_matches "$expected" '^target=[0-9]{1,15};floor=[0-9]{1,15}$' \
                && restore_field_matches "$observed" '^value=([0-9]{1,15}|unknown)$'
            ;;
        cloud_api.ownership | chat_api.ownership)
            [[ "$expected" == "owner=postgres" ]] \
                && restore_field_matches "$observed" '^owner=(postgres|unexpected|missing)$'
            ;;
        cloud_api.uuid_ossp | chat_api.uuid_ossp)
            [[ "$expected" == "extension=present" ]] \
                && restore_field_matches "$observed" '^extension=(present|absent)$'
            ;;
        cloud_api.rename_sentinels)
            [[ "$expected" == "sentinels_present=2" ]] \
                && restore_field_matches "$observed" '^sentinels_present=[0-2]$'
            ;;
        chat_api.response_authors_absent)
            [[ "$expected" == "table=absent" ]] \
                && restore_field_matches "$observed" '^table=(absent|present)$'
            ;;
        cloud_api.table_counts | chat_api.table_counts)
            [[ "$expected" == "table_count_mismatches=0" ]] \
                && restore_field_matches "$observed" '^table_count_mismatches=[0-9]{1,4}$'
            ;;
        cloud_api.max_created_at | chat_api.max_created_at)
            [[ "$expected" == "timestamp_mismatches=0" ]] \
                && restore_field_matches "$observed" '^timestamp_mismatches=[0-9]{1,4}$'
            ;;
        cloud_api.index_count | cloud_api.fk_count | cloud_api.trigger_count | \
        chat_api.index_count | chat_api.fk_count | chat_api.trigger_count | \
        rag_service.index_count | rag_service.fk_count | rag_service.trigger_count | \
        database_*.index_count | database_*.fk_count | database_*.trigger_count)
            { restore_field_matches "$expected" '^count=[0-9]{1,15}$' \
                && restore_field_matches "$observed" '^count=([0-9]{1,15}|unknown)$'; } \
                || { [[ "$expected" == "manifest_format=2" ]] \
                    && [[ "$observed" == "legacy_manifest_skipped" ]]; }
            ;;
        cloud_api.sequences | chat_api.sequences | rag_service.sequences | \
        database_*.sequences)
            [[ "$expected" == "reset_sequences=0" ]] \
                && restore_field_matches "$observed" '^reset_sequences=([0-9]{1,15}|unknown)$'
            ;;
        chat_api.encrypted_columns_fidelity)
            [[ "$expected" == "encrypted_column_mismatches=0" ]] \
                && restore_field_matches "$observed" '^(legacy_manifest_skipped|encrypted_column_mismatches=[0-9]{1,4};encrypted_columns=[0-9]{1,4})$'
            ;;
        cluster.rpo_freshness)
            restore_field_matches "$expected" '^age_seconds<[0-9]{1,15}$' \
                && restore_field_matches "$observed" '^age_seconds=(-?[0-9]{1,15}|unavailable)$'
            ;;
        bucket.drift)
            [[ "$expected" == "drifted_settings=0" ]] \
                && restore_field_matches "$observed" '^(skipped|drifted_settings=[0-5])$'
            ;;
        cluster.rto_within_target)
            restore_field_matches "$expected" '^total_seconds<[0-9]{1,15}$' \
                && restore_field_matches "$observed" '^total_seconds=[0-9]{1,15}$'
            ;;
        *) return 1 ;;
    esac
}

restore_contract_uint() {
    [[ "$1" =~ ^[0-9]+$ ]] || return 1
    RESTORE_CONTRACT_NUMBER=$((10#$1))
}

restore_contract_int() {
    if [[ "$1" == -* ]]; then
        restore_contract_uint "${1#-}" || return 1
        RESTORE_CONTRACT_NUMBER=$((-RESTORE_CONTRACT_NUMBER))
    else
        restore_contract_uint "$1"
    fi
}

restore_check_semantics_valid() {
    local id="$1" expected="$2" observed="$3" pass="$4"
    local should_pass=false first second third fourth

    if [[ "$expected" == "contract_valid" && "$observed" == "contract_violation" ]]; then
        [[ "$pass" == "false" ]]
        return
    fi

    case "$id" in
        cluster.manifest_complete)
            [[ "$observed" == objects_present=* ]] && should_pass=true
            ;;
        cluster.ciphertext_sha256)
            [[ "$observed" =~ ^checksum_mismatches=([0-9]+)\;objects=([0-9]+)$ ]]
            restore_contract_uint "${BASH_REMATCH[1]}"
            (( RESTORE_CONTRACT_NUMBER == 0 )) && should_pass=true
            ;;
        cluster.plaintext_sha256)
            if [[ "$observed" != "key_unavailable" ]]; then
                [[ "$observed" =~ ^decrypt_failures=([0-9]+)\;checksum_mismatches=([0-9]+)\;objects=([0-9]+)$ ]]
                first="${BASH_REMATCH[1]}"
                second="${BASH_REMATCH[2]}"
                restore_contract_uint "$first"
                first="$RESTORE_CONTRACT_NUMBER"
                restore_contract_uint "$second"
                second="$RESTORE_CONTRACT_NUMBER"
                (( first == 0 && second == 0 )) && should_pass=true
            fi
            ;;
        cluster.pg_major)
            first="${expected#major=}"
            second="${observed#major=}"
            if [[ "$first" != "unknown" && "$second" != "unknown" ]]; then
                restore_contract_uint "$first"
                first="$RESTORE_CONTRACT_NUMBER"
                restore_contract_uint "$second"
                second="$RESTORE_CONTRACT_NUMBER"
                (( first == second )) && should_pass=true
            fi
            ;;
        cluster.globals_errors)
            if [[ "$observed" != "decompress_failed" ]]; then
                restore_contract_uint "${observed#non_benign_errors=}"
                (( RESTORE_CONTRACT_NUMBER == 0 )) && should_pass=true
            fi
            ;;
        cluster.app_role_connectivity)
            [[ "$observed" == "login=ok" ]] && should_pass=true
            ;;
        cloud_api.restore_errors | chat_api.restore_errors | rag_service.restore_errors | \
        database_*.restore_errors)
            if [[ "$observed" != "database_drop_failed" ]]; then
                [[ "$observed" =~ ^blocking_errors=([0-9]+)\;total_errors=([0-9]+)\;tolerated_errors=([0-9]+)\;return_code=([0-9]+)$ ]]
                first="${BASH_REMATCH[1]}"
                second="${BASH_REMATCH[2]}"
                third="${BASH_REMATCH[3]}"
                fourth="${BASH_REMATCH[4]}"
                restore_contract_uint "$first"
                first="$RESTORE_CONTRACT_NUMBER"
                restore_contract_uint "$second"
                second="$RESTORE_CONTRACT_NUMBER"
                restore_contract_uint "$third"
                third="$RESTORE_CONTRACT_NUMBER"
                restore_contract_uint "$fourth"
                fourth="$RESTORE_CONTRACT_NUMBER"
                (( second == first + third )) || return 1
                if (( first == 0 )) \
                    && { (( fourth == 0 )) || (( fourth == 1 && third > 0 )); }; then
                    should_pass=true
                fi
            fi
            ;;
        cluster.databases_match)
            [[ "$observed" =~ ^missing_databases=([0-9]+)\;expected_databases=([0-9]+)$ ]]
            restore_contract_uint "${BASH_REMATCH[1]}"
            (( RESTORE_CONTRACT_NUMBER == 0 )) && should_pass=true
            ;;
        cluster.roles)
            if [[ "$observed" != "login_roles=unknown" ]]; then
                restore_contract_uint "${observed#login_roles=}"
                (( RESTORE_CONTRACT_NUMBER == 2 )) && should_pass=true
            fi
            ;;
        cloud_api.migration_version | chat_api.migration_version | \
        cloud_api.migration_row_count | chat_api.migration_row_count)
            [[ "$expected" =~ ^target=([0-9]+)\;floor=([0-9]+)$ ]]
            first="${BASH_REMATCH[1]}"
            second="${BASH_REMATCH[2]}"
            if [[ "$observed" != "value=unknown" ]]; then
                third="${observed#value=}"
                restore_contract_uint "$first"
                first="$RESTORE_CONTRACT_NUMBER"
                restore_contract_uint "$second"
                second="$RESTORE_CONTRACT_NUMBER"
                restore_contract_uint "$third"
                third="$RESTORE_CONTRACT_NUMBER"
                (( third == first && first >= second )) && should_pass=true
            fi
            ;;
        cloud_api.ownership | chat_api.ownership)
            [[ "$observed" == "owner=postgres" ]] && should_pass=true
            ;;
        cloud_api.uuid_ossp | chat_api.uuid_ossp)
            [[ "$observed" == "extension=present" ]] && should_pass=true
            ;;
        cloud_api.rename_sentinels)
            [[ "$observed" == "sentinels_present=2" ]] && should_pass=true
            ;;
        chat_api.response_authors_absent)
            [[ "$observed" == "table=absent" ]] && should_pass=true
            ;;
        cloud_api.table_counts | chat_api.table_counts)
            restore_contract_uint "${observed#table_count_mismatches=}"
            (( RESTORE_CONTRACT_NUMBER == 0 )) && should_pass=true
            ;;
        cloud_api.max_created_at | chat_api.max_created_at)
            restore_contract_uint "${observed#timestamp_mismatches=}"
            (( RESTORE_CONTRACT_NUMBER == 0 )) && should_pass=true
            ;;
        cloud_api.index_count | cloud_api.fk_count | cloud_api.trigger_count | \
        chat_api.index_count | chat_api.fk_count | chat_api.trigger_count | \
        rag_service.index_count | rag_service.fk_count | rag_service.trigger_count | \
        database_*.index_count | database_*.fk_count | database_*.trigger_count)
            if [[ "$expected" == "manifest_format=2" ]]; then
                should_pass=true
            elif [[ "$observed" != "count=unknown" ]]; then
                first="${expected#count=}"
                second="${observed#count=}"
                restore_contract_uint "$first"
                first="$RESTORE_CONTRACT_NUMBER"
                restore_contract_uint "$second"
                second="$RESTORE_CONTRACT_NUMBER"
                (( first == second )) && should_pass=true
            fi
            ;;
        cloud_api.sequences | chat_api.sequences | rag_service.sequences | \
        database_*.sequences)
            if [[ "$observed" != "reset_sequences=unknown" ]]; then
                restore_contract_uint "${observed#reset_sequences=}"
                (( RESTORE_CONTRACT_NUMBER == 0 )) && should_pass=true
            fi
            ;;
        chat_api.encrypted_columns_fidelity)
            if [[ "$observed" == "legacy_manifest_skipped" ]]; then
                should_pass=true
            else
                [[ "$observed" =~ ^encrypted_column_mismatches=([0-9]+)\;encrypted_columns=([0-9]+)$ ]]
                restore_contract_uint "${BASH_REMATCH[1]}"
                (( RESTORE_CONTRACT_NUMBER == 0 )) && should_pass=true
            fi
            ;;
        cluster.rpo_freshness)
            if [[ "$observed" != "age_seconds=unavailable" ]]; then
                first="${expected#age_seconds<}"
                second="${observed#age_seconds=}"
                restore_contract_uint "$first"
                first="$RESTORE_CONTRACT_NUMBER"
                restore_contract_int "$second"
                second="$RESTORE_CONTRACT_NUMBER"
                (( second < first )) && should_pass=true
            fi
            ;;
        bucket.drift)
            [[ "$observed" == "skipped" || "$observed" == "drifted_settings=0" ]] \
                && should_pass=true
            ;;
        cluster.rto_within_target)
            first="${expected#total_seconds<}"
            second="${observed#total_seconds=}"
            restore_contract_uint "$first"
            first="$RESTORE_CONTRACT_NUMBER"
            restore_contract_uint "$second"
            second="$RESTORE_CONTRACT_NUMBER"
            (( second < first )) && should_pass=true
            ;;
        *) return 1 ;;
    esac

    [[ "$pass" == "$should_pass" ]]
}

restore_check_contract_valid() {
    local id="$1" expected="$2" observed="$3" pass="$4"
    restore_check_id_known "$id" || return 1
    restore_check_shape_valid "$id" "$expected" "$observed" "$pass" || return 1
    restore_check_semantics_valid "$id" "$expected" "$observed" "$pass"
}

check_add() {
    local id="$1" expected="$2" observed="$3" pass="$4"
    if ! restore_check_id_known "$id"; then
        id="cluster.manifest_complete"
        expected="contract_valid"
        observed="contract_violation"
        pass=false
        log_error "unknown durable check identifier rejected"
    elif ! restore_check_contract_valid "$id" "$expected" "$observed" "$pass"; then
        expected="contract_valid"
        observed="contract_violation"
        pass=false
        log_error "check ${id}: unsafe durable fields rejected"
    fi
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

restore_notes_sanitize() {
    jq -c --arg app_role "$RESTORE_NOTE_APP_ROLE" \
        --arg unexpected "$RESTORE_NOTE_UNEXPECTED_EXIT" '
        if type != "array" then []
        else [.[] | select(type == "string" and (. == $app_role or . == $unexpected))]
        | unique
        end' <<<"${RESTORE_NOTES:-[]}" 2>/dev/null || echo '[]'
}

restore_error_classes_sanitize() {
    local source="${RESTORE_ERROR_CLASSES:-}"
    [[ -n "$source" ]] || source='{}'
    jq -c '
        def safe_summary:
          test("^(0 lines|[0-9]{1,5} lines \\(((connection|auth|permission|already_exists|missing_object|lock|disk|snapshot|aws|decrypt|other):[0-9]{1,5})( (connection|auth|permission|already_exists|missing_object|lock|disk|snapshot|aws|decrypt|other):[0-9]{1,5})*(, truncated)?\\))$");
        if type != "object" then {}
        else with_entries(select(
          (.key == "globals" or .key == "cloud_api" or .key == "chat_api" or .key == "rag_service"
           or (.key | test("^database_[0-9]{6}$")))
          and (.value | type == "string" and safe_summary)))
        end' <<<"$source" 2>/dev/null || echo '{}'
}

restore_sizes_sanitize() {
    local source="${RESTORE_SIZES:-}"
    [[ -n "$source" ]] || source='{}'
    jq -c '
        def bounded_uint:
          type == "number" and . >= 0 and . <= 999999999999999 and floor == .;
        if type != "object" then {}
        else with_entries(select(
          (.key == "globals" or .key == "cloud_api" or .key == "chat_api" or .key == "rag_service"
           or (.key | test("^database_[0-9]{6}$")))
          and (.value | type == "object" and keys == ["ciphertext_bytes", "plaintext_bytes"])
          and (.value.plaintext_bytes | bounded_uint)
          and (.value.ciphertext_bytes | bounded_uint)))
        end' <<<"$source" 2>/dev/null || echo '{}'
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
    restore_database_scope_known "$scope" || [[ "$scope" == "globals" ]] || return 0
    RESTORE_ERROR_CLASSES=$(jq -c --arg s "$scope" --arg v "$summary" '. + {($s): $v}' \
        <<<"$RESTORE_ERROR_CLASSES")
}

size_add() {
    local name="$1" plain="$2" cipher="$3"
    restore_database_scope_known "$name" || [[ "$name" == "globals" ]] || return 0
    restore_bounded_uint "$plain" >/dev/null || return 0
    restore_bounded_uint "$cipher" >/dev/null || return 0
    RESTORE_SIZES=$(jq -c --arg n "$name" --argjson p "${plain:-0}" --argjson c "${cipher:-0}" \
        '. + {($n): {plaintext_bytes: $p, ciphertext_bytes: $c}}' <<<"$RESTORE_SIZES")
}

# Map captured stderr to the only durable failure categories. Raw lines stay
# inside the CVM; only a fixed enum is retained in RESTORE_FAILURE_CATEGORY.
restore_failure_category_for_line() {
    local line="${1,,}"
    RESTORE_FAILURE_CATEGORY=""
    case "$line" in
        *"could not connect"* | *"connection refused"* | \
        *"server closed the connection"* | *"connection to server was lost"* | \
        *"terminating connection due to administrator command"* | \
        *"could not receive data from server"* | *"could not send data to server"* | \
        *"could not translate host name"* | *"timeout expired"* | \
        *"connection timed out"* | *"no route to host"* | \
        *"the database system is starting up"* | *"the database system is shutting down"*)
            RESTORE_FAILURE_CATEGORY=connection
            ;;
        *"no space left on device"* | *"disk quota exceeded"* | \
        *"could not write to file"* | *"could not extend file"* | \
        *"read-only file system"*)
            RESTORE_FAILURE_CATEGORY=disk
            ;;
        *"out of memory"* | *"cannot allocate memory"* | \
        *"resource temporarily unavailable"* | *"too many open files"* | \
        *"could not fork"* | *"fork failed"* | \
        *"could not resize shared memory segment"*)
            RESTORE_FAILURE_CATEGORY=resource
            ;;
        *)
            return 1
            ;;
    esac
}

restore_postgres_restart_value() {
    local pre="${RESTORE_POSTMASTER_START_PRE:-}"
    local post="${RESTORE_POSTMASTER_START_POST:-}"
    if [[ "$pre" =~ ^[0-9]{1,12}$ && "$post" =~ ^[0-9]{1,12}$ ]]; then
        if [[ "$pre" == "$post" ]]; then
            echo false
        else
            echo true
        fi
    else
        echo unknown
    fi
}

restore_diagnostics_build() {
    local connection=0 disk=0 resource=0 lines=0 truncated=false
    local file line category
    if [[ -n "${RESTORE_STDERR_DIR:-}" ]]; then
        for file in "$RESTORE_STDERR_DIR"/*.stderr; do
            [[ -f "$file" ]] || continue
            while IFS= read -r line || [[ -n "$line" ]]; do
                lines=$(( lines + 1 ))
                if (( lines > RESTORE_DIAGNOSTIC_LINE_LIMIT )); then
                    truncated=true
                    break 2
                fi
                restore_failure_category_for_line "$line" || true
                category="$RESTORE_FAILURE_CATEGORY"
                case "$category" in
                    connection) connection=$(( connection + 1 )) ;;
                    disk) disk=$(( disk + 1 )) ;;
                    resource) resource=$(( resource + 1 )) ;;
                esac
            done < "$file"
        done
    fi

    local restart restart_json
    restart=$(restore_postgres_restart_value)
    if [[ "$restart" == "unknown" ]]; then
        restart_json='"unknown"'
    else
        restart_json="$restart"
    fi

    local scratch_used="${RESTORE_SCRATCH_DISK_USED_PERCENT:-}"
    local scratch_known=false scratch_pressure=unknown scratch_used_number=0
    if [[ "$scratch_used" =~ ^[0-9]{1,3}$ ]] && (( 10#$scratch_used <= 100 )); then
        scratch_known=true
        scratch_used_number=$(( 10#$scratch_used ))
        scratch_pressure=normal
        if (( scratch_used_number >= RESTORE_SCRATCH_DISK_PRESSURE_PERCENT )); then
            scratch_pressure=high
        fi
    fi

    local profile="$RESTORE_PROFILE_LEGACY"
    [[ "${RESTORE_PROFILE:-}" == "$RESTORE_PROFILE_LEGACY" ]] && profile="$RESTORE_PROFILE"
    jq -cn \
        --arg restore_profile "$profile" \
        --argjson connection "$connection" \
        --argjson disk "$disk" \
        --argjson resource "$resource" \
        --argjson truncated "$truncated" \
        --argjson restart "$restart_json" \
        --arg scratch_pressure "$scratch_pressure" \
        --argjson scratch_known "$scratch_known" \
        --argjson scratch_used "$scratch_used_number" \
        '{restore_profile: $restore_profile,
          failure_category_counts: {connection: $connection, disk: $disk, resource: $resource},
          failure_category_counts_truncated: $truncated,
          postgres_restart_observed: $restart,
          scratch_disk_pressure: $scratch_pressure}
         + if $scratch_known then {scratch_disk_used_percent: $scratch_used} else {} end'
}

restore_report_write() {
    local verdict="$1"
    local completed_at rto_total phases_json diagnostics_json error_classes_json notes_json sizes_json
    completed_at=$(date -u +%FT%TZ)
    phases_json="{}"
    local name seconds
    while read -r name seconds; do
        [[ -n "$name" ]] || continue
        phases_json=$(jq -c --arg n "$name" --argjson s "$seconds" '. + {($n): $s}' <<<"$phases_json")
    done < "$RESTORE_PHASES_FILE"
    rto_total=$(( $(date +%s) - RESTORE_START_EPOCH ))
    diagnostics_json=$(restore_diagnostics_build)
    error_classes_json=$(restore_error_classes_sanitize)
    notes_json=$(restore_notes_sanitize)
    sizes_json=$(restore_sizes_sanitize)

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
        --argjson error_classes "$error_classes_json" \
        --argjson sizes "$sizes_json" \
        --argjson diagnostics "$diagnostics_json" \
        --argjson notes "$notes_json" \
        --arg verdict "$verdict" \
        '{format_version: 1,
          drill_id: $drill_id,
          started_at: $started_at, completed_at: $completed_at,
          diagnostics: $diagnostics,
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
        RESTORE_NOTES=$(jq -c --arg note "$RESTORE_NOTE_UNEXPECTED_EXIT" '. + [$note]' <<<"$RESTORE_NOTES")
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

# Sample only enough PostgreSQL state to determine whether its process start
# changed during the drill. Query text/results never enter the report.
restore_postmaster_start_sample() {
    local phase="$1" sampled=""
    sampled=$(rq postgres \
        "SELECT EXTRACT(EPOCH FROM pg_postmaster_start_time())::bigint") || sampled=""
    [[ "$sampled" =~ ^[0-9]{1,12}$ ]] || sampled=""
    case "$phase" in
        pre) RESTORE_POSTMASTER_START_PRE="$sampled" ;;
        post) RESTORE_POSTMASTER_START_POST="$sampled" ;;
        *) return 1 ;;
    esac
    return 0
}

# Retain the highest observed scratch-filesystem utilization. A missing or
# malformed df sample remains unknown rather than being treated as healthy.
restore_scratch_disk_sample() {
    local used="" used_number
    used=$(df -Pk "$RESTORE_WORK_DIR" 2>/dev/null \
        | awk 'NR == 2 { gsub(/%/, "", $5); print $5 }') || used=""
    if [[ "$used" =~ ^[0-9]{1,3}$ ]] && (( 10#$used <= 100 )); then
        used_number=$(( 10#$used ))
        if [[ -z "${RESTORE_SCRATCH_DISK_USED_PERCENT:-}" ]] \
            || (( used_number > RESTORE_SCRATCH_DISK_USED_PERCENT )); then
            RESTORE_SCRATCH_DISK_USED_PERCENT="$used_number"
        fi
    fi
    return 0
}

db_prefix() {
    local index
    case "$1" in
        postgres) echo "cloud_api" ;;
        chat_api) echo "chat_api" ;;
        rag_service) echo "rag_service" ;;
        *)
            for index in "${!RESTORE_DBS[@]}"; do
                if [[ "${RESTORE_DBS[$index]}" == "$1" ]]; then
                    printf 'database_%06d\n' "$(( index + 1 ))"
                    return
                fi
            done
            echo "database_000000"
            ;;
    esac
}

valid_identifier() {
    [[ "$1" =~ ^[a-z_][a-z0-9_]*$ ]]
}

restore_bounded_uint() {
    [[ "$1" =~ ^[0-9]{1,15}$ ]] || return 1
    printf '%s\n' "$1"
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
# decision. Everything else still fails the check. Identifiers are used only
# for this ephemeral classification and never appear in durable reports.
# ---------------------------------------------------------------------------
SPILO_ARTIFACT_EXTENSIONS=(bg_mon pg_auth_mon pg_cron pg_stat_kcache set_user
    pg_permissions file_fdw pg_stat_statements plpython3u plpythonu)
SPILO_ARTIFACT_SCHEMAS=(metric_helpers user_management robot_zmon zalando admin cron zmon_utils)
# Members that Spilo extensions install into the PUBLIC schema; DROP/COMMENT
# statements in dumps reference them by qualified public.* name.
SPILO_ARTIFACT_PUBLIC_MEMBERS=(set_user set_user_u reset_user pg_auth_mon pg_stat_kcache pg_stat_kcache_reset)

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
            # Spilo extensions install some members into public; dumps
            # reference them as public.<member> (or bare <member>).
            local base="${name#public.}"
            for w in "${SPILO_ARTIFACT_PUBLIC_MEMBERS[@]}"; do
                [[ "$base" == "$w" ]] && return 0
            done
            ;;
        language)
            for w in "${SPILO_ARTIFACT_EXTENSIONS[@]}"; do
                [[ "$name" == "$w" ]] && return 0
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
# Object identifiers are used only for the whitelist decision. Durable
# summaries retain fixed kind counters, never identifiers.
restore_classify_errors() {
    local file="$1"
    RESTORE_ERR_TOTAL=0
    RESTORE_ERR_TOLERATED=0
    RESTORE_ERR_BLOCKING=0
    declare -gA RESTORE_ERR_TOLERATED_KIND_COUNTS=()
    declare -gA RESTORE_ERR_BLOCKING_KIND_COUNTS=()
    RESTORE_ERR_BLOCKING_UNCLASSIFIED=0
    [[ -s "$file" ]] || return 0

    # "is not available" is what CREATE EXTENSION emits when the extension
    # files are absent from the server (the vanilla-image case); COMMENT ON /
    # DROP emit "does not exist" for the same root cause.
    local re_ext='extension "([A-Za-z0-9_-]+)" (does not exist|is not available)'
    local re_schema='schema "([A-Za-z0-9_-]+)" does not exist'
    local re_func='function ([A-Za-z0-9_."]+)\([^)]*\) does not exist'
    local re_rel='relation "([A-Za-z0-9_."-]+)" does not exist'
    local re_role='role "([A-Za-z0-9_-]+)" does not exist'
    local re_lang='language "([A-Za-z0-9_]+)" does not exist'

    local line kind name
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
        elif [[ "$line" =~ $re_lang ]]; then
            kind=language name="${BASH_REMATCH[1]}"
        fi
        if [[ -n "$kind" ]] && spilo_artifact_tolerated "$kind" "$name"; then
            RESTORE_ERR_TOLERATED=$(( RESTORE_ERR_TOLERATED + 1 ))
            RESTORE_ERR_TOLERATED_KIND_COUNTS["$kind"]=$((
                ${RESTORE_ERR_TOLERATED_KIND_COUNTS[$kind]:-0} + 1
            ))
        else
            RESTORE_ERR_BLOCKING=$(( RESTORE_ERR_BLOCKING + 1 ))
            if [[ -n "$kind" ]]; then
                RESTORE_ERR_BLOCKING_KIND_COUNTS["$kind"]=$((
                    ${RESTORE_ERR_BLOCKING_KIND_COUNTS[$kind]:-0} + 1
                ))
            else
                RESTORE_ERR_BLOCKING_UNCLASSIFIED=$(( RESTORE_ERR_BLOCKING_UNCLASSIFIED + 1 ))
            fi
        fi
    done < "$file"
    return 0
}

# Render only fixed error kinds and integer counts. The classifier's object
# identifier is deliberately unavailable here and therefore cannot reach a
# check observation or the durable report.
restore_error_kind_summary() {
    local scope="$1" unclassified="${2:-0}" kind count out=""
    for kind in extension schema function relation role language; do
        if [[ "$scope" == "tolerated" ]]; then
            count=${RESTORE_ERR_TOLERATED_KIND_COUNTS[$kind]:-0}
        else
            count=${RESTORE_ERR_BLOCKING_KIND_COUNTS[$kind]:-0}
        fi
        if (( count > 0 )); then
            out+="${out:+, }${kind}:${count}"
        fi
    done
    if (( unclassified > 0 )); then
        out+="${out:+, }unclassified:${unclassified}"
    fi
    echo "$out"
}

restore_blocking_summary() {
    restore_error_kind_summary blocking "$RESTORE_ERR_BLOCKING_UNCLASSIFIED"
}

restore_tolerated_summary() {
    restore_error_kind_summary tolerated 0
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
        check_add "cluster.manifest_complete" "manifest_complete" "download_failed" false
        return 1
    }
    if ! jq -e '.format_version and .backup_id and .databases and .globals and .encryption.key_path' \
        "$RESTORE_WORK_DIR/manifest.json" >/dev/null 2>&1; then
        check_add "cluster.manifest_complete" "manifest_complete" "manifest_invalid" false
        return 1
    fi
    if ! RESTORE_PROFILE=$(manifest_restore_profile_resolve \
        "$RESTORE_WORK_DIR/manifest.json"); then
        check_add "cluster.manifest_complete" "manifest_complete" \
            "restore_profile_unsupported" false
        return 1
    fi

    RESTORE_BACKUP_PREFIX=$(dirname "$RESTORE_MANIFEST_KEY")
    mapfile -t RESTORE_DBS < <(jq -r '.databases[].name' "$RESTORE_WORK_DIR/manifest.json")

    local obj db
    obj=$(jq -r '.globals.object' "$RESTORE_WORK_DIR/manifest.json")
    s3_get_file "${RESTORE_BACKUP_PREFIX}/${obj}" "$RESTORE_WORK_DIR/enc/${obj}" || {
        check_add "cluster.manifest_complete" "manifest_complete" "globals_object_missing" false
        return 1
    }
    for db in "${RESTORE_DBS[@]}"; do
        obj=$(jq -r --arg db "$db" '.databases[] | select(.name == $db) | .object' \
            "$RESTORE_WORK_DIR/manifest.json")
        s3_get_file "${RESTORE_BACKUP_PREFIX}/${obj}" "$RESTORE_WORK_DIR/enc/${obj}" || {
            check_add "cluster.manifest_complete" "manifest_complete" "database_object_missing" false
            return 1
        }
    done
    check_add "cluster.manifest_complete" "manifest_complete" \
        "objects_present=$(( ${#RESTORE_DBS[@]} + 1 ))" true
    phase_record download $(( SECONDS - t0 ))
}

restore_verify_ciphertext() {
    local t0=$SECONDS total=0 bad_count=0
    local obj want got
    while IFS=$'\t' read -r obj want; do
        total=$(( total + 1 ))
        got=$(sha256sum "$RESTORE_WORK_DIR/enc/${obj}" | awk '{print $1}')
        [[ "$got" == "$want" ]] || bad_count=$(( bad_count + 1 ))
    done < <(jq -r '([.globals] + .databases)[] | [.object, .sha256_ciphertext] | @tsv' \
        "$RESTORE_WORK_DIR/manifest.json")

    if (( bad_count == 0 )); then
        check_add "cluster.ciphertext_sha256" "checksum_mismatches=0" \
            "checksum_mismatches=0;objects=${total}" true
    else
        check_add "cluster.ciphertext_sha256" "checksum_mismatches=0" \
            "checksum_mismatches=${bad_count};objects=${total}" false
        return 1
    fi
    phase_record verify_ciphertext $(( SECONDS - t0 ))
}

restore_decrypt() {
    local t0=$SECONDS total=0 decrypt_failures=0 plaintext_mismatches=0
    local key_path
    key_path=$(jq -r '.encryption.key_path' "$RESTORE_WORK_DIR/manifest.json")
    fetch_encryption_key "$key_path" || {
        check_add "cluster.plaintext_sha256" "decrypt_failures=0;checksum_mismatches=0" \
            "key_unavailable" false
        return 1
    }

    local obj want got plain scope_raw scope
    while IFS=$'\t' read -r obj want; do
        total=$(( total + 1 ))
        plain="$RESTORE_WORK_DIR/plain/${obj%.enc}"
        if ! openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_ENCRYPTION_KEY \
            -in "$RESTORE_WORK_DIR/enc/${obj}" -out "$plain" \
            2>"$RESTORE_STDERR_DIR/decrypt.stderr"; then
            decrypt_failures=$(( decrypt_failures + 1 ))
            continue
        fi
        got=$(sha256sum "$plain" | awk '{print $1}')
        [[ "$got" == "$want" ]] || plaintext_mismatches=$(( plaintext_mismatches + 1 ))
        scope_raw=$(jq -r --arg obj "$obj" '
            if .globals.object == $obj then "globals"
            else (.databases[] | select(.object == $obj) | .name)
            end' "$RESTORE_WORK_DIR/manifest.json")
        if [[ "$scope_raw" == "globals" ]]; then
            scope=globals
        else
            scope=$(db_prefix "$scope_raw")
        fi
        size_add "$scope" "$(wc -c <"$plain")" "$(wc -c <"$RESTORE_WORK_DIR/enc/${obj}")"
    done < <(jq -r '([.globals] + .databases)[] | [.object, .sha256_plaintext] | @tsv' \
        "$RESTORE_WORK_DIR/manifest.json")

    if (( decrypt_failures == 0 && plaintext_mismatches == 0 )); then
        check_add "cluster.plaintext_sha256" "decrypt_failures=0;checksum_mismatches=0" \
            "decrypt_failures=0;checksum_mismatches=0;objects=${total}" true
    else
        check_add "cluster.plaintext_sha256" "decrypt_failures=0;checksum_mismatches=0" \
            "decrypt_failures=${decrypt_failures};checksum_mismatches=${plaintext_mismatches};objects=${total}" false
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
    restore_postmaster_start_sample pre
}

restore_pg_major_gate() {
    local expected_raw observed_raw expected=unknown observed=unknown
    expected_raw=$(jq -r '.source.pg_version' "$RESTORE_WORK_DIR/manifest.json" | cut -d. -f1)
    observed_raw=$(rq postgres "SHOW server_version" | cut -d. -f1)
    expected=$(restore_bounded_uint "$expected_raw") || expected=unknown
    observed=$(restore_bounded_uint "$observed_raw") || observed=unknown
    if [[ "$expected" != "unknown" && "$observed" == "$expected" ]]; then
        check_add "cluster.pg_major" "major=${expected}" "major=${observed}" true
    else
        check_add "cluster.pg_major" "major=${expected}" "major=${observed}" false
        return 1
    fi
}

restore_globals() {
    local t0=$SECONDS
    gunzip -c "$RESTORE_WORK_DIR/plain/globals.sql.gz" > "$RESTORE_WORK_DIR/plain/globals.sql" || {
        check_add "cluster.globals_errors" "non_benign_errors=0" "decompress_failed" false
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

    local errors summary errors_safe
    errors=$(stderr_count_errors "$RESTORE_STDERR_DIR/globals.stderr" "already exists")
    summary=$(stderr_summarize "$RESTORE_STDERR_DIR/globals.stderr")
    error_class_add "globals" "$summary"
    errors_safe=$(restore_bounded_uint "$errors") || errors_safe=1
    if [[ "$errors_safe" == "0" ]]; then
        check_add "cluster.globals_errors" "non_benign_errors=0" \
            "non_benign_errors=0" true
    else
        check_add "cluster.globals_errors" "non_benign_errors=0" \
            "non_benign_errors=${errors_safe}" false
    fi

    # Fresh SCRAM TCP login with the drill password must now work.
    local probe
    probe=$(rq postgres "SELECT 1") || probe=""
    if [[ "$probe" == "1" ]]; then
        check_add "cluster.app_role_connectivity" "login=ok" "login=ok" true
    else
        check_add "cluster.app_role_connectivity" "login=ok" "login=failed" false
        return 1
    fi
    phase_record globals $(( SECONDS - t0 ))
}

restore_databases() {
    local t0=$SECONDS db prefix dumpfile summary rc
    for db in "${RESTORE_DBS[@]}"; do
        prefix=$(db_prefix "$db")
        dumpfile="$RESTORE_WORK_DIR/plain/${db}.dump"
        log_info "Restoring ${db}..."

        # Uniform drop-first (idempotent for reruns; the maintenance DB is
        # template1 so the 'postgres' database itself can be recreated).
        rq template1 "DROP DATABASE IF EXISTS \"${db}\" WITH (FORCE)" >/dev/null || {
            check_add "${prefix}.restore_errors" "blocking_errors=0" "database_drop_failed" false
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
        error_class_add "$prefix" "$summary"
        if (( RESTORE_ERR_BLOCKING == 0 )) \
            && { [[ "$rc" -eq 0 ]] || { [[ "$rc" -eq 1 ]] && (( RESTORE_ERR_TOLERATED > 0 )); }; }; then
            check_add "${prefix}.restore_errors" "blocking_errors=0" \
                "blocking_errors=0;total_errors=${RESTORE_ERR_TOTAL};tolerated_errors=${RESTORE_ERR_TOLERATED};return_code=${rc}" true
        else
            check_add "${prefix}.restore_errors" "blocking_errors=0" \
                "blocking_errors=${RESTORE_ERR_BLOCKING};total_errors=${RESTORE_ERR_TOTAL};tolerated_errors=${RESTORE_ERR_TOLERATED};return_code=${rc}" false
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
    local observed missing=0 db expected_databases=${#RESTORE_DBS[@]}
    observed=$(rq postgres "SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname" | tr '\n' ' ')
    for db in "${RESTORE_DBS[@]}"; do
        [[ " $observed " == *" $db "* ]] || missing=$(( missing + 1 ))
    done
    if (( missing == 0 )); then
        check_add "cluster.databases_match" "missing_databases=0" \
            "missing_databases=0;expected_databases=${expected_databases}" true
    else
        check_add "cluster.databases_match" "missing_databases=0" \
            "missing_databases=${missing};expected_databases=${expected_databases}" false
    fi

    # Required roles present and login-capable.
    local roles
    roles=$(rq postgres "SELECT COUNT(*) FROM pg_roles WHERE rolname IN ('postgres','datadog') AND rolcanlogin")
    if [[ "$roles" == "2" ]]; then
        check_add "cluster.roles" "login_roles=2" "login_roles=2" true
    else
        roles=$(restore_bounded_uint "$roles") || roles=unknown
        check_add "cluster.roles" "login_roles=2" "login_roles=${roles}" false
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
        local want_ver_raw want_rows_raw got_ver_raw got_rows_raw
        want_ver_raw=$(jq -r '.max_version' <<<"$mig")
        want_rows_raw=$(jq -r '.row_count' <<<"$mig")
        case "$prefix" in
            cloud_api) floor_ver=$RESTORE_FLOOR_CLOUD_API_VERSION; floor_rows=$RESTORE_FLOOR_CLOUD_API_ROWS ;;
            chat_api) floor_ver=$RESTORE_FLOOR_CHAT_API_VERSION; floor_rows=$RESTORE_FLOOR_CHAT_API_ROWS ;;
        esac
        got_ver_raw=$(rq "$db" "SELECT COALESCE(MAX(version), 0) FROM public.refinery_schema_history")
        got_rows_raw=$(rq "$db" "SELECT COUNT(*) FROM public.refinery_schema_history")
        want_ver=$(restore_bounded_uint "$want_ver_raw") || want_ver=unknown
        want_rows=$(restore_bounded_uint "$want_rows_raw") || want_rows=unknown
        got_ver=$(restore_bounded_uint "$got_ver_raw") || got_ver=unknown
        got_rows=$(restore_bounded_uint "$got_rows_raw") || got_rows=unknown
        if [[ "$want_ver" != "unknown" && "$got_ver" == "$want_ver" ]] \
            && (( 10#$got_ver >= floor_ver )); then
            check_add "${prefix}.migration_version" "target=${want_ver};floor=${floor_ver}" "value=${got_ver}" true
        else
            check_add "${prefix}.migration_version" "target=${want_ver};floor=${floor_ver}" "value=${got_ver}" false
        fi
        if [[ "$want_rows" != "unknown" && "$got_rows" == "$want_rows" ]] \
            && (( 10#$got_rows >= floor_rows )); then
            check_add "${prefix}.migration_row_count" "target=${want_rows};floor=${floor_rows}" "value=${got_rows}" true
        else
            check_add "${prefix}.migration_row_count" "target=${want_rows};floor=${floor_rows}" "value=${got_rows}" false
        fi

        # Ownership spot-check: pg_restore ran without --no-owner, so the
        # migrations table must carry its original owner (postgres).
        local owner
        owner=$(rq "$db" "SELECT tableowner FROM pg_tables WHERE schemaname='public' AND tablename='refinery_schema_history'")
        if [[ "$owner" == "postgres" ]]; then
            check_add "${prefix}.ownership" "owner=postgres" "owner=postgres" true
        elif [[ -z "$owner" ]]; then
            check_add "${prefix}.ownership" "owner=postgres" "owner=missing" false
        else
            check_add "${prefix}.ownership" "owner=postgres" "owner=unexpected" false
        fi
    fi

    # uuid-ossp (cloud-api + chat-api databases).
    if [[ "$db" == "postgres" || "$db" == "chat_api" ]]; then
        local ext
        ext=$(rq "$db" "SELECT COUNT(*) FROM pg_extension WHERE extname='uuid-ossp'")
        if [[ "$ext" == "1" ]]; then
            check_add "${prefix}.uuid_ossp" "extension=present" "extension=present" true
        else
            check_add "${prefix}.uuid_ossp" "extension=present" "extension=absent" false
        fi
    fi

    # Rename sentinels / dropped-table sentinel.
    if [[ "$db" == "postgres" ]]; then
        local s1 s2
        s1=$(rq "$db" "SELECT to_regclass('public.refresh_tokens') IS NOT NULL")
        s2=$(rq "$db" "SELECT to_regclass('public.model_history') IS NOT NULL")
        local sentinels_present=0
        [[ "$s1" == "t" ]] && sentinels_present=$(( sentinels_present + 1 ))
        [[ "$s2" == "t" ]] && sentinels_present=$(( sentinels_present + 1 ))
        if (( sentinels_present == 2 )); then
            check_add "cloud_api.rename_sentinels" "sentinels_present=2" "sentinels_present=2" true
        else
            check_add "cloud_api.rename_sentinels" "sentinels_present=2" \
                "sentinels_present=${sentinels_present}" false
        fi
    fi
    if [[ "$db" == "chat_api" ]]; then
        local gone
        gone=$(rq "$db" "SELECT to_regclass('public.response_authors') IS NULL")
        if [[ "$gone" == "t" ]]; then
            check_add "chat_api.response_authors_absent" "table=absent" "table=absent" true
        else
            check_add "chat_api.response_authors_absent" "table=absent" "table=present" false
        fi
    fi

    # Representative-table counts + MAX(created_at) vs manifest.
    local tables_total=0 count_bad=0 ts_bad=0 newest_created=""
    local t want_count want_ts got is_churn tolerance lo hi timestamp_safe
    while IFS=$'\t' read -r t want_count want_ts; do
        valid_identifier "$t" || continue
        tables_total=$(( tables_total + 1 ))
        want_count=$(restore_bounded_uint "$want_count") || {
            count_bad=$(( count_bad + 1 ))
            continue
        }
        got=$(rq "$db" "SELECT COUNT(*) FROM public.\"${t}\"")
        if [[ "$snapshot_consistent" == "true" ]]; then
            [[ "$got" == "$want_count" ]] || count_bad=$(( count_bad + 1 ))
        else
            is_churn=0
            [[ " $RESTORE_HIGH_CHURN_TABLES " == *" $t "* ]] && is_churn=1
            if [[ "$is_churn" -eq 1 ]]; then
                tolerance=$(( want_count / 50 + 100 ))
                lo=$(( want_count - tolerance )); hi=$(( want_count + tolerance ))
                { [[ "$got" =~ ^[0-9]{1,15}$ ]] && (( 10#$got >= lo && 10#$got <= hi )); } \
                    || count_bad=$(( count_bad + 1 ))
            else
                [[ "$got" == "$want_count" ]] || count_bad=$(( count_bad + 1 ))
            fi
        fi
        if [[ -n "$want_ts" && "$want_ts" != "null" ]]; then
            timestamp_safe=$(date -u -d "$want_ts" +%Y-%m-%dT%H:%M:%S.%6NZ 2>/dev/null) || timestamp_safe=""
            if [[ -z "$timestamp_safe" ]]; then
                ts_bad=$(( ts_bad + 1 ))
                continue
            fi
            if [[ "$snapshot_consistent" == "true" ]]; then
                got=$(rq "$db" "SELECT MAX(created_at) = '${timestamp_safe}'::timestamptz FROM public.\"${t}\"")
            else
                got=$(rq "$db" "SELECT MAX(created_at) >= '${timestamp_safe}'::timestamptz FROM public.\"${t}\"")
            fi
            [[ "$got" == "t" ]] || ts_bad=$(( ts_bad + 1 ))
            if [[ -z "$newest_created" || "$timestamp_safe" > "$newest_created" ]]; then
                newest_created="$timestamp_safe"
            fi
        fi
    done < <(jq -r --arg db "$db" \
        '.databases[] | select(.name == $db) | .validation.tables | to_entries[] | [.key, (.value.count | tostring), (.value.max_created_at // "null")] | @tsv' \
        "$RESTORE_WORK_DIR/manifest.json")

    if (( tables_total > 0 )); then
        if (( count_bad == 0 )); then
            check_add "${prefix}.table_counts" "table_count_mismatches=0" \
                "table_count_mismatches=0" true
        else
            check_add "${prefix}.table_counts" "table_count_mismatches=0" \
                "table_count_mismatches=${count_bad}" false
        fi
        if (( ts_bad == 0 )); then
            check_add "${prefix}.max_created_at" "timestamp_mismatches=0" "timestamp_mismatches=0" true
        else
            check_add "${prefix}.max_created_at" "timestamp_mismatches=0" "timestamp_mismatches=${ts_bad}" false
        fi
    fi
    # Track the globally newest row timestamp for the RPO check.
    if [[ -n "$newest_created" ]]; then
        if [[ -z "${RESTORE_NEWEST_CREATED_AT:-}" || "$newest_created" > "$RESTORE_NEWEST_CREATED_AT" ]]; then
            RESTORE_NEWEST_CREATED_AT="$newest_created"
        fi
    fi

    # Index / FK / trigger counts vs manifest. Manifests below format 2 were
    # produced with GLOBAL (unscoped) counts; comparing them against the
    # drill's public-schema-scoped counts is apples to oranges — skip-pass
    # with a note until the backup side runs a format>=2 image.
    local manifest_format manifest_format_raw
    manifest_format_raw=$(jq -r '.format_version // 1' "$RESTORE_WORK_DIR/manifest.json")
    manifest_format=$(restore_bounded_uint "$manifest_format_raw") || manifest_format=unknown
    local want got_n name query want_raw got_raw
    for name in index_count fk_count trigger_count; do
        if [[ "$manifest_format" == "unknown" ]]; then
            check_add "${prefix}.${name}" "contract_valid" "contract_violation" false
            continue
        fi
        if (( 10#$manifest_format < 2 )); then
            check_add "${prefix}.${name}" "manifest_format=2" "legacy_manifest_skipped" true
            continue
        fi
        want_raw=$(jq -r --arg db "$db" --arg k "$name" \
            '.databases[] | select(.name == $db) | .validation[$k]' "$RESTORE_WORK_DIR/manifest.json")
        want=$(restore_bounded_uint "$want_raw") || want=unknown
        # Shared public-schema-scoped SQL from lib/pg.sh — the manifest side
        # runs the exact same statements, so both sides compare like for like.
        case "$name" in
            index_count) query="$PG_SQL_INDEX_COUNT" ;;
            fk_count) query="$PG_SQL_FK_COUNT" ;;
            trigger_count) query="$PG_SQL_TRIGGER_COUNT" ;;
        esac
        got_raw=$(rq "$db" "$query")
        got_n=$(restore_bounded_uint "$got_raw") || got_n=unknown
        if [[ "$want" != "unknown" && "$got_n" == "$want" ]]; then
            check_add "${prefix}.${name}" "count=${want}" "count=${got_n}" true
        else
            check_add "${prefix}.${name}" "count=${want}" "count=${got_n}" false
        fi
    done

    # Sequences non-reset: no never-called sequence may own a non-empty table.
    local seq_bad seq_bad_raw
    seq_bad_raw=$(rq "$db" "
        SELECT COUNT(*) FROM pg_sequences ps
        JOIN pg_class seqc ON seqc.relname = ps.sequencename AND seqc.relkind = 'S'
        JOIN pg_namespace ns ON ns.oid = seqc.relnamespace AND ns.nspname = ps.schemaname
        JOIN pg_depend d ON d.objid = seqc.oid AND d.deptype IN ('a','i')
        JOIN pg_class tbl ON tbl.oid = d.refobjid AND tbl.relkind = 'r'
        WHERE ps.schemaname = 'public' AND ps.last_value IS NULL AND tbl.reltuples > 0")
    seq_bad=$(restore_bounded_uint "$seq_bad_raw") || seq_bad=unknown
    if [[ "$seq_bad" == "0" ]]; then
        check_add "${prefix}.sequences" "reset_sequences=0" "reset_sequences=0" true
    else
        check_add "${prefix}.sequences" "reset_sequences=0" "reset_sequences=${seq_bad}" false
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
        check_add "chat_api.encrypted_columns_fidelity" "encrypted_column_mismatches=0" \
            "legacy_manifest_skipped" true
        return 0
    fi

    local cols_total=0 bad_count=0 key want_total want_well tbl col pair got_total got_well
    while IFS=$'\t' read -r key want_total want_well; do
        [[ -n "$key" ]] || continue
        cols_total=$(( cols_total + 1 ))
        tbl="${key%%.*}"
        col="${key#*.}"
        if ! valid_identifier "$tbl" || ! valid_identifier "$col"; then
            bad_count=$(( bad_count + 1 ))
            continue
        fi
        pair=$(rq "$db" "SELECT COUNT(\"${col}\") || ' ' || COUNT(*) FILTER (WHERE \"${col}\" ~ '${PG_CIPHERTEXT_REGEX}') FROM public.\"${tbl}\"") || pair=""
        got_total="${pair%% *}"
        got_well="${pair##* }"
        if ! restore_bounded_uint "$want_total" >/dev/null \
            || ! restore_bounded_uint "$want_well" >/dev/null \
            || ! restore_bounded_uint "$got_total" >/dev/null \
            || ! restore_bounded_uint "$got_well" >/dev/null \
            || [[ "$got_total" != "$want_total" || "$got_well" != "$want_well" ]]; then
            bad_count=$(( bad_count + 1 ))
        fi
    done < <(jq -r 'to_entries[] | [.key, (.value.total | tostring), (.value.wellformed | tostring)] | @tsv' \
        <<<"$encfmt")

    if (( cols_total == 0 )); then
        check_add "chat_api.encrypted_columns_fidelity" "encrypted_column_mismatches=0" \
            "encrypted_column_mismatches=0;encrypted_columns=0" true
    elif (( bad_count == 0 )); then
        check_add "chat_api.encrypted_columns_fidelity" "encrypted_column_mismatches=0" \
            "encrypted_column_mismatches=0;encrypted_columns=${cols_total}" true
    else
        check_add "chat_api.encrypted_columns_fidelity" "encrypted_column_mismatches=0" \
            "encrypted_column_mismatches=${bad_count};encrypted_columns=${cols_total}" false
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
                check_add "cluster.rpo_freshness" "age_seconds<${RESTORE_RPO_TARGET_SECONDS}" \
                    "age_seconds=${age}" true
            else
                check_add "cluster.rpo_freshness" "age_seconds<${RESTORE_RPO_TARGET_SECONDS}" \
                    "age_seconds=${age}" false
            fi
            return 0
        fi
    fi
    check_add "cluster.rpo_freshness" "age_seconds<${RESTORE_RPO_TARGET_SECONDS}" \
        "age_seconds=unavailable" false
}

validate_bucket_drift() {
    if [[ "$RESTORE_BUCKET_CHECK" != "true" ]]; then
        check_add "bucket.drift" "drifted_settings=0" "skipped" true
        return 0
    fi
    local bad=0 v
    v=$(aws s3api get-bucket-versioning --bucket "$S3_BUCKET" --query Status --output text 2>/dev/null) || v=""
    [[ "$v" == "Enabled" ]] || bad=$(( bad + 1 ))
    v=$(aws s3api get-object-lock-configuration --bucket "$S3_BUCKET" \
        --query 'ObjectLockConfiguration.Rule.DefaultRetention.Mode' --output text 2>/dev/null) || v=""
    [[ "$v" == "GOVERNANCE" ]] || bad=$(( bad + 1 ))
    v=$(aws s3api get-public-access-block --bucket "$S3_BUCKET" \
        --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' \
        --output text 2>/dev/null | tr '\t' ',') || v=""
    [[ "$v" == "True,True,True,True" ]] || bad=$(( bad + 1 ))
    v=$(aws s3api get-bucket-encryption --bucket "$S3_BUCKET" \
        --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
        --output text 2>/dev/null) || v=""
    [[ "$v" == "AES256" ]] || bad=$(( bad + 1 ))
    v=$(aws s3api get-bucket-lifecycle-configuration --bucket "$S3_BUCKET" \
        --query 'length(Rules)' --output text 2>/dev/null) || v=""
    [[ "$v" =~ ^[0-9]{1,15}$ && "$v" -ge 1 ]] || bad=$(( bad + 1 ))

    if (( bad == 0 )); then
        check_add "bucket.drift" "drifted_settings=0" "drifted_settings=0" true
    else
        check_add "bucket.drift" "drifted_settings=0" "drifted_settings=${bad}" false
    fi
}

validate_rto() {
    local total=$(( $(date +%s) - RESTORE_START_EPOCH ))
    if (( total < RESTORE_RTO_TARGET_SECONDS )); then
        check_add "cluster.rto_within_target" "total_seconds<${RESTORE_RTO_TARGET_SECONDS}" \
            "total_seconds=${total}" true
    else
        check_add "cluster.rto_within_target" "total_seconds<${RESTORE_RTO_TARGET_SECONDS}" \
            "total_seconds=${total}" false
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
    restore_scratch_disk_sample
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
    restore_postmaster_start_sample post
    restore_scratch_disk_sample
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
