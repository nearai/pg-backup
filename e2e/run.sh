#!/usr/bin/env bash
# End-to-end test: seed a source cluster, let the sidecar produce an
# encrypted backup in MinIO, independently verify checksums + pg_restore
# --list, then run the full restore drill (PG_BACKUP_MODE=restore) against a
# fresh postgres and diff row counts source vs restored.
#
# Usage: ./run.sh            (build, run, tear down)
#        KEEP=1 ./run.sh     (leave the stack up for debugging)
set -euo pipefail

cd "$(dirname "$0")"

COMPOSE=(docker compose)
BUCKET=pg-backup-e2e

fail() {
    echo "[e2e] FAIL: $*" >&2
    exit 1
}

cleanup() {
    if [[ "${KEEP:-0}" == "1" ]]; then
        echo "[e2e] KEEP=1 — leaving the stack running"
        return 0
    fi
    "${COMPOSE[@]}" --profile restore down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# aws CLI inside the sidecar container. The entrypoint maps BACKUP_AWS_* to
# AWS_* only for the daemon process, so exec'd commands get them explicitly.
AWSENV=(-e AWS_ACCESS_KEY_ID=e2eaccesskey -e AWS_SECRET_ACCESS_KEY=e2esecretkey
    -e AWS_DEFAULT_REGION=us-east-1)

s3() {
    "${COMPOSE[@]}" exec -T "${AWSENV[@]}" pg-backup bash -c "aws $*"
}

src_psql() {
    local db="$1" sql="$2"
    "${COMPOSE[@]}" exec -T postgres psql -U postgres -d "$db" -Atc "$sql"
}

restored_psql() {
    # Local socket auth (trust) — the drill rotates the SCRAM password.
    local db="$1" sql="$2"
    "${COMPOSE[@]}" exec -T restore-pg psql -U postgres -d "$db" -Atc "$sql"
}

echo "[e2e] Building image..."
docker build -q -t pg-backup-e2e .. >/dev/null

mkdir -p .state/setup
printf 'e2e-source-pw' > .state/setup/postgres-password
printf 'e2e-source-host\n' > .state/setup/actual_hostname

echo "[e2e] Starting postgres + minio + patroni-mock + restore-pg..."
"${COMPOSE[@]}" up -d --wait postgres restore-pg minio patroni-mock

echo "[e2e] Seeding source cluster..."
"${COMPOSE[@]}" exec -T postgres psql -U postgres -v ON_ERROR_STOP=1 -q -f - < seed.sql

echo "[e2e] Creating bucket..."
"${COMPOSE[@]}" run --rm --no-deps --entrypoint bash "${AWSENV[@]}" pg-backup -c \
    "aws s3 mb s3://${BUCKET}" >/dev/null

echo "[e2e] Starting backup sidecar..."
"${COMPOSE[@]}" up -d pg-backup

echo "[e2e] Waiting for a completed backup (manifest + latest.json)..."
MANIFEST_KEY=""
for _ in $(seq 1 90); do
    LATEST=$(s3 "s3 cp s3://${BUCKET}/control/latest.json - 2>/dev/null" || true)
    if [[ -n "$LATEST" ]]; then
        MANIFEST_KEY=$(jq -r '.manifest_key // empty' <<<"$LATEST")
        [[ -n "$MANIFEST_KEY" ]] && break
    fi
    sleep 2
done
[[ -n "$MANIFEST_KEY" ]] || {
    "${COMPOSE[@]}" logs pg-backup | tail -50
    fail "no completed backup after timeout"
}
echo "[e2e] Backup complete: ${MANIFEST_KEY}"

MANIFEST=$(s3 "s3 cp s3://${BUCKET}/${MANIFEST_KEY} -")
BACKUP_PREFIX=$(dirname "$MANIFEST_KEY")

echo "[e2e] Verifying manifest contents..."
for db in postgres chat_api rag_service; do
    jq -e --arg db "$db" '.databases[] | select(.name == $db)' <<<"$MANIFEST" >/dev/null \
        || fail "manifest missing database $db"
done
[[ "$(jq -r '.source.snapshot_consistent' <<<"$MANIFEST")" == "true" ]] \
    || fail "expected snapshot-consistent counts on a healthy source"
[[ "$(jq -r '.databases[] | select(.name == "postgres") | .validation.tables.organizations.count' <<<"$MANIFEST")" == "25" ]] \
    || fail "manifest organizations count != seeded 25"
[[ "$(jq -r '.databases[] | select(.name == "postgres") | .migrations.max_version' <<<"$MANIFEST")" == "63" ]] \
    || fail "manifest cloud-api migration version != 63"
[[ "$(jq -r '.databases[] | select(.name == "chat_api") | .migrations.row_count' <<<"$MANIFEST")" == "33" ]] \
    || fail "manifest chat-api migration rows != 33"

echo "[e2e] Independent decrypt + checksum + pg_restore --list..."
"${COMPOSE[@]}" exec -T "${AWSENV[@]}" pg-backup bash -c "
    set -euo pipefail
    cd /run/backup
    aws s3 cp s3://${BUCKET}/${MANIFEST_KEY} ./manifest.json --quiet
    want_cipher=\$(jq -r '.databases[] | select(.name == \"postgres\") | .sha256_ciphertext' manifest.json)
    want_plain=\$(jq -r '.databases[] | select(.name == \"postgres\") | .sha256_plaintext' manifest.json)
    aws s3 cp s3://${BUCKET}/${BACKUP_PREFIX}/postgres.dump.enc ./postgres.dump.enc --quiet
    got_cipher=\$(sha256sum postgres.dump.enc | awk '{print \$1}')
    [[ \"\$got_cipher\" == \"\$want_cipher\" ]] || { echo ciphertext-sha-mismatch; exit 1; }
    openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_ENCRYPTION_KEY \
        -in postgres.dump.enc -out postgres.dump
    got_plain=\$(sha256sum postgres.dump | awk '{print \$1}')
    [[ \"\$got_plain\" == \"\$want_plain\" ]] || { echo plaintext-sha-mismatch; exit 1; }
    pg_restore --list postgres.dump | grep -q 'TABLE DATA public organizations' \
        || { echo missing-table-in-toc; exit 1; }
    rm -f postgres.dump postgres.dump.enc manifest.json
" || fail "independent decrypt/verify failed"

echo "[e2e] Metrics endpoint..."
METRICS=$("${COMPOSE[@]}" exec -T pg-backup curl -s http://localhost:9464/metrics)
grep -q '^nearai_postgres_backup_last_success_timestamp_seconds ' <<<"$METRICS" \
    || fail "metrics missing last_success series"
grep -q 'nearai_postgres_backup_dump_size_bytes{database="postgres"}' <<<"$METRICS" \
    || fail "metrics missing dump_size series"

echo "[e2e] Running restore drill..."
DRILL_ID="$(date -u +%FT%H%MZ)-e2e"
export RESTORE_MANIFEST_KEY="$MANIFEST_KEY" DRILL_ID
DRILL_RC=0
"${COMPOSE[@]}" --profile restore run --rm restore-driver || DRILL_RC=$?

REPORT=$(s3 "s3 cp s3://${BUCKET}/restore-reports/${DRILL_ID}.json -" || true)
[[ -n "$REPORT" ]] || fail "no restore report uploaded"
VERDICT=$(jq -r '.verdict' <<<"$REPORT")
FAILED_CHECKS=$(jq -r '[.checks[] | select(.pass | not) | .id] | join(", ")' <<<"$REPORT")
echo "[e2e] Drill verdict: ${VERDICT} (exit ${DRILL_RC}) checks: $(jq '.checks | length' <<<"$REPORT")"
[[ "$VERDICT" == "PASS" && "$DRILL_RC" -eq 0 ]] \
    || fail "drill FAIL (rc=${DRILL_RC}); failed checks: ${FAILED_CHECKS:-none}"

echo "[e2e] Source vs restored count diff..."
for spec in "postgres:organizations" "postgres:users" "chat_api:users" \
    "chat_api:sessions" "chat_api:agent_instances" "rag_service:documents"; do
    db="${spec%%:*}"; table="${spec##*:}"
    src=$(src_psql "$db" "SELECT COUNT(*) FROM ${table}")
    dst=$(restored_psql "$db" "SELECT COUNT(*) FROM ${table}")
    [[ -n "$src" && "$src" == "$dst" ]] \
        || fail "count mismatch ${db}.${table}: source=${src} restored=${dst}"
done

echo "[e2e] PASS — backup, verify, restore drill, and count diff all green"
