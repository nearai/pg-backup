#!/usr/bin/env bash
# Distributed locking via an S3 object (ported from cvm-ingress lib/lock.sh,
# jq-parsed). Lock object: control/locks/backup.lock with JSON body
# {"holder": "...", "acquired_at": <epoch>, "ttl_seconds": <n>}.
#
# Semantics are last-writer-wins with TTL takeover: a fresh lock held by
# another member is respected; a stale or unparsable lock is taken over. A
# background renewal loop refreshes acquired_at every BACKUP_LOCK_RENEW_SECONDS
# while a run is in progress, so the TTL only expires on a dead holder.

LOCK_KEY="control/locks/backup.lock"
LOCK_RENEWAL_PID=""
# shellcheck disable=SC2034  # read by the entrypoint's shutdown trap
LOCK_HELD=0

# Evaluate a lock JSON document. Pure function (testable without S3).
# Args: <json> <now_epoch> <self_holder>
# Prints one of: invalid | expired | self | held
lock_evaluate() {
    local json="$1"
    local now="$2"
    local self="$3"

    local holder acquired_at ttl
    holder=$(jq -r '.holder // empty' <<<"$json" 2>/dev/null) || holder=""
    acquired_at=$(jq -r '.acquired_at // empty' <<<"$json" 2>/dev/null) || acquired_at=""
    ttl=$(jq -r '.ttl_seconds // empty' <<<"$json" 2>/dev/null) || ttl=""

    if [[ -z "$holder" || -z "$acquired_at" || -z "$ttl" ]] \
        || ! [[ "$acquired_at" =~ ^[0-9]+$ && "$ttl" =~ ^[0-9]+$ ]]; then
        echo "invalid"
        return 0
    fi

    local age=$(( now - acquired_at ))
    if (( age >= ttl )); then
        echo "expired"
    elif [[ "$holder" == "$self" ]]; then
        echo "self"
    else
        echo "held"
    fi
}

lock_render() {
    local holder="$1"
    local acquired_at="$2"
    local ttl="$3"
    jq -n --arg holder "$holder" --argjson acquired_at "$acquired_at" --argjson ttl "$ttl" \
        '{holder: $holder, acquired_at: $acquired_at, ttl_seconds: $ttl}'
}

lock_write() {
    lock_render "$MEMBER_HOST" "$(date +%s)" "$BACKUP_LOCK_TTL_SECONDS" \
        | s3_put_stream "$LOCK_KEY"
}

acquire_lock() {
    local now state json
    now=$(date +%s)

    if s3_exists "$LOCK_KEY"; then
        json=$(s3_get_stdout "$LOCK_KEY" 2>/dev/null) || json=""
        state=$(lock_evaluate "$json" "$now" "$MEMBER_HOST")
        case "$state" in
            held)
                log_warn "Lock held by $(jq -r '.holder' <<<"$json") (age: $(( now - $(jq -r '.acquired_at' <<<"$json") ))s), skipping this cycle"
                return 1
                ;;
            expired)
                log_warn "Stale lock from $(jq -r '.holder' <<<"$json"), taking over"
                ;;
            invalid)
                log_warn "Unparsable lock object, taking over"
                ;;
            self)
                log_warn "Lock already held by this member, refreshing"
                ;;
        esac
    fi

    lock_write || return 1
    LOCK_HELD=1
    log_info "Lock acquired by $MEMBER_HOST"
    return 0
}

release_lock() {
    lock_renewal_stop
    # shellcheck disable=SC2034  # read by the entrypoint's shutdown trap
    LOCK_HELD=0
    s3_delete "$LOCK_KEY" || {
        log_warn "Failed to release lock"
        return 1
    }
    log_info "Lock released"
}

# Refresh acquired_at in the background while a run is in progress so the
# lock survives runs longer than the TTL (dump can take longer than 1800s).
lock_renewal_start() {
    lock_renewal_stop
    (
        while true; do
            sleep "$BACKUP_LOCK_RENEW_SECONDS"
            lock_write || log_warn "Lock renewal failed"
        done
    ) &
    LOCK_RENEWAL_PID=$!
}

lock_renewal_stop() {
    if [[ -n "$LOCK_RENEWAL_PID" ]]; then
        kill "$LOCK_RENEWAL_PID" 2>/dev/null || true
        wait "$LOCK_RENEWAL_PID" 2>/dev/null || true
        LOCK_RENEWAL_PID=""
    fi
}
