#!/usr/bin/env bash
# Logging helpers + sanitized stderr classification.
#
# pg_dump/pg_restore/psql stderr can embed row values (e.g. in COPY error
# context), so raw stderr must NEVER be logged, uploaded, or echoed. It is
# captured to tmpfs and summarized here as whitelisted error classes with
# line counts only.

log_info() {
    echo "[INFO]  $(date -u '+%Y-%m-%d %H:%M:%S') $*"
}

log_warn() {
    echo "[WARN]  $(date -u '+%Y-%m-%d %H:%M:%S') $*" >&2
}

log_error() {
    echo "[ERROR] $(date -u '+%Y-%m-%d %H:%M:%S') $*" >&2
}

# Classify one stderr line into a whitelisted error class. First match wins.
# Prints the class name; never prints the line itself.
stderr_classify_line() {
    local line="$1"
    case "$line" in
        *"could not connect"* | *"Connection refused"* | *"connection refused"* | \
        *"server closed the connection"* | *"could not translate host name"* | \
        *"timeout expired"* | *"no route to host"* | \
        *"the database system is starting up"* | *"the database system is shutting down"*)
            echo "connection" ;;
        *"password authentication failed"* | *"no password supplied"* | *"authentication failed"*)
            echo "auth" ;;
        *"permission denied"* | *"must be superuser"*)
            echo "permission" ;;
        *"invalid snapshot identifier"* | *"snapshot "*" does not exist"*)
            echo "snapshot" ;;
        *"already exists"*)
            echo "already_exists" ;;
        *"does not exist"*)
            echo "missing_object" ;;
        *"lock timeout"* | *"deadlock detected"*)
            echo "lock" ;;
        *"No space left on device"* | *"could not write to file"* | *"could not extend file"*)
            echo "disk" ;;
        *"An error occurred"* | *"Could not connect to the endpoint URL"* | *"upload failed"* | \
        *"SSL validation failed"* | *"Read timeout"*)
            echo "aws" ;;
        *"bad decrypt"* | *"bad magic number"*)
            echo "decrypt" ;;
        *)
            echo "other" ;;
    esac
}

# Summarize a captured stderr file as "N lines (class:count ...)".
# Prints "0 lines" for a missing or empty file. Caps processing at 20000
# lines (summary is then marked truncated). Never echoes file content.
stderr_summarize() {
    local file="$1"
    if [[ ! -s "$file" ]]; then
        echo "0 lines"
        return 0
    fi

    local line class total=0 truncated=""
    declare -A counts=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        total=$((total + 1))
        if [[ "$total" -gt 20000 ]]; then
            truncated=", truncated"
            break
        fi
        class=$(stderr_classify_line "$line")
        counts[$class]=$(( ${counts[$class]:-0} + 1 ))
    done < "$file"

    local summary="" c
    for c in connection auth permission already_exists missing_object lock disk snapshot aws decrypt other; do
        if [[ -n "${counts[$c]:-}" ]]; then
            summary+="${summary:+ }${c}:${counts[$c]}"
        fi
    done
    echo "${total} lines (${summary}${truncated})"
}

# Count ERROR lines in a captured stderr file, excluding a benign pattern.
# Used for globals restore where only "already exists" is acceptable.
# Prints the count; never echoes content.
stderr_count_errors() {
    local file="$1"
    local benign_pattern="${2:-}"
    if [[ ! -s "$file" ]]; then
        echo 0
        return 0
    fi
    local count
    if [[ -n "$benign_pattern" ]]; then
        count=$(grep -cE 'ERROR:|FATAL:|error:' "$file" 2>/dev/null || true)
        local benign
        benign=$(grep -E 'ERROR:|FATAL:|error:' "$file" 2>/dev/null | grep -cE "$benign_pattern" || true)
        count=$(( ${count:-0} - ${benign:-0} ))
    else
        count=$(grep -cE 'ERROR:|FATAL:|error:' "$file" 2>/dev/null || true)
    fi
    echo "${count:-0}"
}
