# pg-backup

Encrypted logical PostgreSQL backups to S3 for the Patroni cluster CVMs,
plus the restore drill driver used by the monthly automated recovery test
(nearai/infra#189). Runs as the `pg-backup` sidecar in the postgres CVM
compose (see cvm-ansible-playbooks `cvm_configurations/postgres.yaml.j2`).

## What it does

**Backup mode** (`PG_BACKUP_MODE=backup`, default) — a tick daemon that:

- runs a nightly cycle at `BACKUP_SCHEDULE_UTC` (02:30, restart-proof and
  self-backfilling via `control/latest.json`), an optional soak interval
  (`BACKUP_INTERVAL_SECONDS`), and manual triggers
  (`control/triggers/manual-<run_id>.json`, written by the
  `backup_postgres_now` workflow);
- only runs on the Patroni leader (REST role + `pg_is_in_recovery()` on the
  dump connection, re-checked immediately before `pg_dump`), serialized by
  an S3 lock with TTL + renewal;
- streams every non-template database and the globals dump through
  `pg_dump -Fc | openssl enc -aes-256-cbc | aws s3 cp -` — no plaintext ever
  touches disk; sha256/size taps hang off the stream;
- captures snapshot-consistent validation counts (`pg_export_snapshot` +
  `pg_dump --snapshot`) so the restore drill can assert exact equality;
- uploads `backups/<BACKUP_ID>/manifest.json` **last** — manifest presence
  means the backup is complete; partial prefixes are lifecycle-reaped;
- serves Prometheus metrics on `:9464` (scraped by the in-CVM otelcol via
  the `nearai.otel.*` compose labels).

**Restore mode** (`PG_BACKUP_MODE=restore`) — one-shot drill driver:
download → ciphertext sha256 → decrypt → plaintext sha256 → PG major gate →
globals via psql → per-db `pg_restore --create -j4` → validation battery
(migration versions, exact table counts, index/FK/trigger counts, rename
sentinels, RPO/RTO vs targets) → sanitized report JSON to
`restore-reports/<DRILL_ID>.json`, exit code by verdict.

## Encryption

The AES-256 key comes from the dstack guest agent at runtime
(`GetKey?path=$BACKUP_KEY_PATH`, default `/postgres-backup/enc-v1`) — 
deterministic per (app_id, path), so a drill CVM under the same app_id
re-derives it and **no human-held key material exists anywhere**. Rotation =
bump the key path; the manifest records which path encrypted each backup.
If the dstack KMS root is irrecoverably lost, backups are unrecoverable
(accepted trade-off, documented in infra-docs `docs/postgres-backups.md`).

`BACKUP_KEY_SOURCE=env` is a test-only escape hatch used by the e2e harness.

## Privacy

`pg_dump`/`pg_restore`/`psql` stderr can embed row values. It is captured to
tmpfs, summarized as whitelisted error classes + line counts, and never
logged, uploaded, or included in reports. Reports and manifests carry
counts, IDs, checksums and durations only.

## Configuration

See `entrypoint.sh` (`validate_backup_env` / `restore_validate_env`) for the
full `BACKUP_*` / `RESTORE_*` env surface and defaults. The production
values are wired in cvm-ansible-playbooks (`postgres.yaml.j2` + deploy
playbooks); the env-var *names* are attested in the compose hash, values
ride the CVM env file.

## Build & release

```bash
./build-image.sh                      # reproducible OCI archive (oci.tar)
./build-image.sh --push nearaidev/pg-backup:staging
```

Same harness as cvm-ingress: pinned BuildKit, `SOURCE_DATE_EPOCH=0`,
rewrite-timestamp; `pinned-packages.txt` is regenerated from the built image
and CI fails on drift. The base is the same `postgres:16-alpine` digest as
`postgres_alpine_image` in cvm-ansible-playbooks `image_versions.yaml`
(pg_dump 16 matches Spilo-16). After publishing, pin the new digest as
`pg_backup_image` there.

## Tests

```bash
shellcheck -x entrypoint.sh lib/*.sh
bats tests/          # cycle math, stderr classifier, manifest, lock, metrics
./e2e/run.sh         # full backup → verify → restore drill against MinIO
```

## Operations

- Force a backup now: run the `backup_postgres_now` workflow
  (cvm-ansible-playbooks) — it writes the S3 trigger marker; the leader's
  sidecar picks it up within a tick.
- Restore drill: `postgres_restore_test` workflow (monthly + manual).
- Alerts and the full runbook (failure triage, DR procedure, key rotation):
  infra-docs `docs/postgres-backups.md`.
