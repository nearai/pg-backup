#!/usr/bin/env bash
# Manifest + control/latest.json construction (metadata only — never row
# content). Contract: backups/<BACKUP_ID>/manifest.json is uploaded LAST,
# only after every dump and the globals object succeeded. Manifest presence
# == backup complete; partial prefixes are never referenced and are reaped
# by the bucket lifecycle.

MANIFEST_FORMAT_VERSION=1
LATEST_KEY="control/latest.json"
LATEST_PENDING_FILE="/run/backup/latest.pending.json"

# One per-database manifest entry.
# Args: name object db_size_bytes plain_size cipher_size plain_sha cipher_sha
#       collect_json ({migrations: ..., validation: ...} from pg_collect_validation)
manifest_db_entry() {
    local name="$1" object="$2" db_size_bytes="$3"
    local plain_size="$4" cipher_size="$5" plain_sha="$6" cipher_sha="$7"
    local collect_json="$8"

    jq -n \
        --arg name "$name" \
        --arg object "$object" \
        --argjson db_size_bytes "${db_size_bytes:-0}" \
        --argjson plain_size "$plain_size" \
        --argjson cipher_size "$cipher_size" \
        --arg plain_sha "$plain_sha" \
        --arg cipher_sha "$cipher_sha" \
        --argjson collect "$collect_json" \
        '{name: $name, object: $object,
          db_size_bytes: $db_size_bytes,
          size_bytes_plaintext: $plain_size, size_bytes_ciphertext: $cipher_size,
          sha256_plaintext: $plain_sha, sha256_ciphertext: $cipher_sha,
          migrations: $collect.migrations,
          validation: $collect.validation}'
}

# Full manifest document.
# Args: backup_id cycle_key trigger cluster env started_at completed_at
#       duration_s member_host pg_version snapshot_consistent(bool)
#       globals_json databases_json(array) key_path retention_days
manifest_build() {
    local backup_id="$1" cycle_key="$2" trigger="$3" cluster="$4" env_name="$5"
    local started_at="$6" completed_at="$7" duration_s="$8"
    local member_host="$9" pg_version="${10}" snapshot_consistent="${11}"
    local globals_json="${12}" databases_json="${13}"
    local key_path="${14}" retention_days="${15}"

    local consistency="per-database-snapshot"
    [[ "$snapshot_consistent" == "true" ]] || consistency="post-dump-counts"

    local tool_versions
    tool_versions=$(jq -n \
        --arg pg_dump "$(pg_dump --version | awk '{print $NF}')" \
        --arg aws_cli "$(aws --version 2>&1 | awk '{print $1}' | cut -d/ -f2)" \
        --arg openssl "$(openssl version | awk '{print $2}')" \
        '{pg_dump: $pg_dump, aws_cli: $aws_cli, openssl: $openssl}')

    jq -n \
        --argjson format_version "$MANIFEST_FORMAT_VERSION" \
        --arg backup_id "$backup_id" \
        --arg cycle_key "$cycle_key" \
        --arg trigger "$trigger" \
        --arg cluster "$cluster" \
        --arg env "$env_name" \
        --arg started_at "$started_at" \
        --arg completed_at "$completed_at" \
        --argjson duration_seconds "$duration_s" \
        --arg member_host "$member_host" \
        --arg pg_version "$pg_version" \
        --arg consistency "$consistency" \
        --argjson snapshot_consistent "$snapshot_consistent" \
        --arg key_path "$key_path" \
        --argjson globals "$globals_json" \
        --argjson databases "$databases_json" \
        --argjson tool_versions "$tool_versions" \
        --argjson retention_days "$retention_days" \
        '{format_version: $format_version,
          backup_id: $backup_id,
          cycle_key: $cycle_key,
          trigger: $trigger,
          cluster: $cluster, env: $env,
          started_at: $started_at, completed_at: $completed_at,
          duration_seconds: $duration_seconds,
          source: {member_host: $member_host, patroni_role: "leader",
                   pg_is_in_recovery: false, pg_version: $pg_version,
                   consistency: $consistency,
                   snapshot_consistent: $snapshot_consistent},
          encryption: {mode: "openssl-aes-256-cbc-pbkdf2", key_path: $key_path},
          globals: $globals,
          databases: $databases,
          tool_versions: $tool_versions,
          retention_days: $retention_days}'
}

manifest_globals_entry() {
    local plain_sha="$1" cipher_sha="$2" plain_size="$3" cipher_size="$4"
    jq -n \
        --arg plain_sha "$plain_sha" --arg cipher_sha "$cipher_sha" \
        --argjson plain_size "$plain_size" --argjson cipher_size "$cipher_size" \
        '{object: "globals.sql.gz.enc",
          sha256_plaintext: $plain_sha, sha256_ciphertext: $cipher_sha,
          size_bytes_plaintext: $plain_size, size_bytes_ciphertext: $cipher_size}'
}

# control/latest.json body. Only scheduled runs advance last_scheduled_cycle:
# a manual backup must not suppress the nightly, so a manual run carries the
# previous cycle value forward.
latest_build() {
    local backup_id="$1" manifest_key="$2" completed_at="$3" trigger="$4"
    local last_scheduled_cycle="$5"
    jq -n \
        --arg backup_id "$backup_id" \
        --arg manifest_key "$manifest_key" \
        --arg completed_at "$completed_at" \
        --arg trigger "$trigger" \
        --arg cycle "$last_scheduled_cycle" \
        '{backup_id: $backup_id, manifest_key: $manifest_key,
          completed_at: $completed_at, trigger: $trigger,
          last_scheduled_cycle: (if $cycle == "" then null else $cycle end)}'
}

latest_fetch() {
    s3_get_stdout "$LATEST_KEY" 2>/dev/null
}

# Upload latest.json with retries. On persistent failure the payload is
# parked in tmpfs and retried by latest_repair_tick from the main loop —
# the backup itself is complete (its manifest exists), so the run is not
# failed over a pointer update.
latest_update() {
    local payload="$1"
    local attempt
    for attempt in 1 2 3; do
        if echo "$payload" | s3_put_stream "$LATEST_KEY"; then
            rm -f "$LATEST_PENDING_FILE"
            return 0
        fi
        log_warn "latest.json update failed (attempt ${attempt}/3)"
        sleep $(( attempt * 5 ))
    done
    echo "$payload" > "$LATEST_PENDING_FILE"
    log_error "latest.json update failed; parked for repair"
    return 1
}

latest_repair_tick() {
    [[ -s "$LATEST_PENDING_FILE" ]] || return 0
    if s3_put_stream "$LATEST_KEY" < "$LATEST_PENDING_FILE"; then
        rm -f "$LATEST_PENDING_FILE"
        log_info "Repaired pending latest.json update"
    else
        log_warn "latest.json repair still failing"
    fi
    return 0
}
