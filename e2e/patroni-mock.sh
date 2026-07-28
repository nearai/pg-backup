#!/usr/bin/env bash
# Minimal Patroni REST stand-in for the e2e harness: always answers
# {"role": "leader"} on :8008 so the sidecar's leader gate passes (the
# pg_is_in_recovery() half of the gate runs against the real e2e postgres).
set -euo pipefail

# shellcheck disable=SC2016  # evaluated by the per-connection sh, not here
RESPONDER='while read -r l; do l="${l%$(printf "\r")}"; [ -z "$l" ] && break; done; printf "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"; printf "{\"role\": \"leader\"}\n"'

RESPONDER_FILE=/tmp/patroni-mock-responder.sh
printf '%s\n' "$RESPONDER" > "$RESPONDER_FILE"
chmod +x "$RESPONDER_FILE"

exec socat TCP-LISTEN:8008,fork,reuseaddr SYSTEM:"sh ${RESPONDER_FILE}"
