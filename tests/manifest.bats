#!/usr/bin/env bats
# Manifest + latest.json construction (jq assertions on the shapes the
# restore drill depends on).

load test_helper

setup() {
    source_entrypoint
}

collect_fixture() {
    jq -n '{migrations: {table: "refinery_schema_history", max_version: 63, row_count: 62},
            validation: {snapshot_consistent: true,
                         tables: {organizations: {count: 12, max_created_at: "2026-07-28 01:02:03+00"}},
                         index_count: 40, fk_count: 11, trigger_count: 13}}'
}

@test "manifest_db_entry: shape and values" {
    local entry
    entry=$(manifest_db_entry postgres postgres.dump.enc 123456789 \
        1000 1042 aaaa1111 bbbb2222 "$(collect_fixture)")
    [ "$(jq -r '.name' <<<"$entry")" = "postgres" ]
    [ "$(jq -r '.object' <<<"$entry")" = "postgres.dump.enc" ]
    [ "$(jq -r '.db_size_bytes' <<<"$entry")" = "123456789" ]
    [ "$(jq -r '.size_bytes_plaintext' <<<"$entry")" = "1000" ]
    [ "$(jq -r '.size_bytes_ciphertext' <<<"$entry")" = "1042" ]
    [ "$(jq -r '.sha256_plaintext' <<<"$entry")" = "aaaa1111" ]
    [ "$(jq -r '.sha256_ciphertext' <<<"$entry")" = "bbbb2222" ]
    [ "$(jq -r '.migrations.max_version' <<<"$entry")" = "63" ]
    [ "$(jq -r '.validation.tables.organizations.count' <<<"$entry")" = "12" ]
    [ "$(jq -r '.validation.snapshot_consistent' <<<"$entry")" = "true" ]
}

@test "manifest_db_entry: null migrations pass through (rag_service)" {
    local collect entry
    collect=$(jq -n '{migrations: null,
                      validation: {snapshot_consistent: true, tables: {},
                                   index_count: 2, fk_count: 0, trigger_count: 0}}')
    entry=$(manifest_db_entry rag_service rag_service.dump.enc 1024 10 42 aa bb "$collect")
    [ "$(jq -r '.migrations' <<<"$entry")" = "null" ]
}

@test "manifest_build: full document contract" {
    local entry dbs globals manifest
    entry=$(manifest_db_entry postgres postgres.dump.enc 123 1000 1042 aaaa bbbb "$(collect_fixture)")
    dbs=$(jq -n --argjson e "$entry" '[$e]')
    globals=$(manifest_globals_entry cccc dddd 500 542)
    manifest=$(manifest_build "2026-07-28T0230Z-3f9a1c" "2026-07-28" scheduled \
        postgres-prod prod "2026-07-28T02:30:01Z" "2026-07-28T02:43:33Z" 812 \
        cpu01-vm 16.11 true "$globals" "$dbs" /postgres-backup/enc-v1 30)

    [ "$(jq -r '.format_version' <<<"$manifest")" = "1" ]
    [ "$(jq -r '.backup_id' <<<"$manifest")" = "2026-07-28T0230Z-3f9a1c" ]
    [ "$(jq -r '.cycle_key' <<<"$manifest")" = "2026-07-28" ]
    [ "$(jq -r '.trigger' <<<"$manifest")" = "scheduled" ]
    [ "$(jq -r '.source.member_host' <<<"$manifest")" = "cpu01-vm" ]
    [ "$(jq -r '.source.patroni_role' <<<"$manifest")" = "leader" ]
    [ "$(jq -r '.source.pg_is_in_recovery' <<<"$manifest")" = "false" ]
    [ "$(jq -r '.source.consistency' <<<"$manifest")" = "per-database-snapshot" ]
    [ "$(jq -r '.source.snapshot_consistent' <<<"$manifest")" = "true" ]
    [ "$(jq -r '.encryption.mode' <<<"$manifest")" = "openssl-aes-256-cbc-pbkdf2" ]
    [ "$(jq -r '.encryption.key_path' <<<"$manifest")" = "/postgres-backup/enc-v1" ]
    [ "$(jq -r '.globals.object' <<<"$manifest")" = "globals.sql.gz.enc" ]
    [ "$(jq -r '.databases | length' <<<"$manifest")" = "1" ]
    [ "$(jq -r '.duration_seconds' <<<"$manifest")" = "812" ]
    [ "$(jq -r '.retention_days' <<<"$manifest")" = "30" ]
    [ "$(jq -r '.tool_versions.pg_dump' <<<"$manifest")" = "16.11" ]
}

@test "manifest_build: snapshot fallback flips consistency" {
    local entry dbs globals manifest
    entry=$(manifest_db_entry postgres postgres.dump.enc 123 1000 1042 aaaa bbbb "$(collect_fixture)")
    dbs=$(jq -n --argjson e "$entry" '[$e]')
    globals=$(manifest_globals_entry cccc dddd 500 542)
    manifest=$(manifest_build id key "manual:manual-123" postgres-staging staging \
        s c 10 host 16.11 false "$globals" "$dbs" /postgres-backup/enc-v1 7)
    [ "$(jq -r '.source.consistency' <<<"$manifest")" = "post-dump-counts" ]
    [ "$(jq -r '.source.snapshot_consistent' <<<"$manifest")" = "false" ]
}

@test "latest_build: scheduled run advances the cycle" {
    local latest
    latest=$(latest_build "2026-07-28T0230Z-3f9a1c" "backups/2026-07-28T0230Z-3f9a1c/manifest.json" \
        "2026-07-28T02:43:33Z" scheduled "2026-07-28")
    [ "$(jq -r '.backup_id' <<<"$latest")" = "2026-07-28T0230Z-3f9a1c" ]
    [ "$(jq -r '.manifest_key' <<<"$latest")" = "backups/2026-07-28T0230Z-3f9a1c/manifest.json" ]
    [ "$(jq -r '.last_scheduled_cycle' <<<"$latest")" = "2026-07-28" ]
}

@test "latest_build: manual run with no prior cycle stores null" {
    local latest
    latest=$(latest_build id key ts "manual:manual-99" "")
    [ "$(jq -r '.trigger' <<<"$latest")" = "manual:manual-99" ]
    [ "$(jq '.last_scheduled_cycle' <<<"$latest")" = "null" ]
}
