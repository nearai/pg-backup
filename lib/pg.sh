#!/usr/bin/env bash
# PostgreSQL helpers: leader gate, database enumeration, and the
# snapshot-consistent validation-count session.
#
# The leader gate is checked twice per run (at owed-evaluation and again
# immediately before pg_dump) and combines the Patroni REST role with
# pg_is_in_recovery() on the actual dump connection — Patroni state alone
# has been wrong during switchovers.
#
# Validation counts are captured in a long-lived psql session that exports a
# snapshot (BEGIN ISOLATION LEVEL REPEATABLE READ; SELECT pg_export_snapshot())
# which pg_dump then reuses via --snapshot, so the restore drill can assert
# exact count equality. If snapshot export fails, counts are taken after the
# dump and the manifest is marked snapshot_consistent=false.

# Representative tables per logical database (contract with the restore
# drill; count + MAX(created_at) recorded in the manifest).
PG_REP_TABLES_POSTGRES="organizations users workspaces api_keys models organization_usage_log responses response_items organization_balance"
PG_REP_TABLES_CHAT_API="users oauth_accounts sessions conversations user_usage_event agent_instances subscriptions stripe_customers"

pg_rep_tables() {
    local db="$1"
    case "$db" in
        postgres) echo "$PG_REP_TABLES_POSTGRES" ;;
        chat_api) echo "$PG_REP_TABLES_CHAT_API" ;;
        *) echo "" ;;
    esac
}

pg_password() {
    if [[ -n "${BACKUP_PG_PASSWORD:-}" ]]; then
        echo "$BACKUP_PG_PASSWORD"
    else
        cat "${BACKUP_PG_PASSWORD_FILE:-/setup/postgres-password}"
    fi
}

# One-shot query against a database. Rows on stdout (unaligned, tuples
# only); stderr appended to $PG_STDERR_FILE (content-bearing, tmpfs only).
pg_psql() {
    local db="$1"
    local sql="$2"
    PGPASSWORD="$(pg_password)" PGAPPNAME="nearai-backup" \
        PGOPTIONS="-c lock_timeout=30s -c statement_timeout=0" \
        psql -X -q -A -t --no-password \
        -h "$BACKUP_PG_HOST" -p "$BACKUP_PG_PORT" -U postgres -d "$db" \
        -c "$sql" 2>>"${PG_STDERR_FILE:-/dev/null}"
}

patroni_role() {
    curl -fsS --max-time 10 \
        "http://${BACKUP_PATRONI_HOST}:${BACKUP_PATRONI_PORT}/" 2>/dev/null \
        | jq -r '.role // empty'
}

# Leader gate: Patroni role AND pg_is_in_recovery() on the dump connection.
# Accepts leader/master/primary (role naming differs across Patroni versions).
leader_gate() {
    local role
    role=$(patroni_role) || role=""
    case "$role" in
        leader | master | primary) ;;
        *)
            log_info "Patroni role is '${role:-unknown}', not leader"
            return 1
            ;;
    esac

    local in_recovery
    in_recovery=$(pg_psql postgres "SELECT pg_is_in_recovery()") || in_recovery=""
    if [[ "$in_recovery" != "f" ]]; then
        log_info "pg_is_in_recovery() returned '${in_recovery:-error}', not primary"
        return 1
    fi
    return 0
}

pg_server_version() {
    pg_psql postgres "SHOW server_version"
}

# All non-template, connectable databases, minus BACKUP_EXCLUDE_DATABASES
# (comma-separated). Dynamic so rag_service and future databases are covered.
pg_list_databases() {
    local db excluded
    while IFS= read -r db; do
        [[ -n "$db" ]] || continue
        excluded=0
        if [[ -n "${BACKUP_EXCLUDE_DATABASES:-}" ]]; then
            local ex
            for ex in ${BACKUP_EXCLUDE_DATABASES//,/ }; do
                [[ "$db" == "$ex" ]] && excluded=1
            done
        fi
        [[ "$excluded" -eq 0 ]] && echo "$db"
    done < <(pg_psql postgres "SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname")
}

pg_database_size() {
    local db="$1"
    pg_psql postgres "SELECT pg_database_size('${db}')"
}

# ---------------------------------------------------------------------------
# Long-lived psql session (bash coproc) for snapshot-consistent counts.
# ---------------------------------------------------------------------------

PG_SESSION_OPEN=0

pg_session_open() {
    local db="$1"
    local stderr_file="$2"
    # shellcheck disable=SC2034  # PGSESSION fds are used via ${PGSESSION[*]}
    coproc PGSESSION {
        PGPASSWORD="$(pg_password)" PGAPPNAME="nearai-backup" \
            PGOPTIONS="-c lock_timeout=30s -c statement_timeout=0" \
            psql -X -q -A -t --no-password \
            -h "$BACKUP_PG_HOST" -p "$BACKUP_PG_PORT" -U postgres -d "$db" \
            2>>"$stderr_file"
    }
    PG_SESSION_OPEN=1
}

# Run SQL in the session; result rows go to stdout until an echoed sentinel.
# Returns 1 on read timeout / closed session. Statements must be guarded
# (to_regclass etc.) — an error would abort the REPEATABLE READ transaction
# and invalidate the exported snapshot.
#
# IMPORTANT: coproc file descriptors are not visible in subshells, so these
# functions must NEVER be called through command substitution $(...). They
# run in the main shell and hand results back via redirection or the
# PG_SESSION_RESULT global.
pg_session_sql() {
    local sql="$1"
    local timeout="${BACKUP_QUERY_TIMEOUT_SECONDS:-600}"
    local sentinel="__DONE_${RANDOM}${RANDOM}__"

    # The lone ";" line terminates the statement (backslash commands execute
    # immediately, SQL only on a terminator — without this the sentinel would
    # arrive while the query is still sitting in psql's buffer). A trailing
    # ";" in $sql just adds an empty query, which psql silently skips.
    printf '%s\n;\n\\echo %s\n' "$sql" "$sentinel" >&"${PGSESSION[1]}" || return 1

    local line
    while IFS= read -r -t "$timeout" line <&"${PGSESSION[0]}"; do
        if [[ "$line" == "$sentinel" ]]; then
            return 0
        fi
        echo "$line"
    done
    return 1
}

# Single-value wrapper: last non-empty result line into PG_SESSION_RESULT.
PG_SESSION_RESULT=""
pg_session_scalar() {
    local sql="$1"
    local outfile
    outfile=$(mktemp "${PG_SESSION_TMPDIR:-/tmp}/session_result.XXXXXX") || return 1
    if ! pg_session_sql "$sql" > "$outfile"; then
        rm -f "$outfile"
        return 1
    fi
    PG_SESSION_RESULT=$(awk 'NF {last=$0} END {print last}' "$outfile")
    rm -f "$outfile"
}

pg_session_close() {
    if [[ "$PG_SESSION_OPEN" -eq 1 ]]; then
        if [[ -n "${PGSESSION[1]:-}" ]]; then
            { printf '\\q\n' >&"${PGSESSION[1]}"; } 2>/dev/null || true
        fi
        local rfd="${PGSESSION[0]:-}" wfd="${PGSESSION[1]:-}"
        [[ -n "$rfd" ]] && { exec {rfd}<&- ; } 2>/dev/null
        [[ -n "$wfd" ]] && { exec {wfd}>&- ; } 2>/dev/null
        wait "${PGSESSION_PID:-}" 2>/dev/null || true
        PG_SESSION_OPEN=0
    fi
    return 0
}

# Begin a REPEATABLE READ transaction and export its snapshot. The id lands
# in PG_SNAPSHOT_ID; returns 1 (caller falls back to post-dump counts).
PG_SNAPSHOT_ID=""
pg_snapshot_begin() {
    PG_SNAPSHOT_ID=""
    pg_session_scalar "BEGIN ISOLATION LEVEL REPEATABLE READ; SELECT pg_export_snapshot();" || return 1
    if [[ ! "$PG_SESSION_RESULT" =~ ^[0-9A-Fa-f-]+$ ]]; then
        return 1
    fi
    # shellcheck disable=SC2034  # consumed by the entrypoint run loop
    PG_SNAPSHOT_ID="$PG_SESSION_RESULT"
}

# ---------------------------------------------------------------------------
# Validation-count collection (session or direct), emitted as JSON:
# {migrations: {...}|null,
#  validation: {snapshot_consistent, tables: {...}, index_count, fk_count,
#               trigger_count}}
# ---------------------------------------------------------------------------

# Internal: run a query through the chosen runner; result lands in
# PG_RUN_RESULT (no command substitution — the session runner talks to the
# coproc, whose fds do not exist in subshells).
#   $1 = runner ("session" uses the open coproc; "direct" one-shot psql)
#   $2 = database (direct runner only)
#   $3 = sql
PG_RUN_RESULT=""
pg_run_query() {
    local runner="$1"
    local db="$2"
    local sql="$3"
    if [[ "$runner" == "session" ]]; then
        pg_session_scalar "$sql" || return 1
        PG_RUN_RESULT="$PG_SESSION_RESULT"
    else
        PG_RUN_RESULT=$(pg_psql "$db" "$sql") || return 1
    fi
}

# Collect validation counts; the JSON document lands in PG_COLLECT_JSON.
PG_COLLECT_JSON=""
pg_collect_validation() {
    local db="$1"
    local runner="$2"           # session | direct
    local snapshot_consistent="$3"  # true | false

    PG_COLLECT_JSON=""
    local tables_json="{}" t count max_created
    local rep_tables
    rep_tables=$(pg_rep_tables "$db")
    for t in $rep_tables; do
        pg_run_query "$runner" "$db" "SELECT to_regclass('public.${t}') IS NOT NULL" || return 1
        [[ "$PG_RUN_RESULT" == "t" ]] || continue
        pg_run_query "$runner" "$db" "SELECT COUNT(*) FROM public.${t}" || return 1
        count="$PG_RUN_RESULT"
        [[ "$count" =~ ^[0-9]+$ ]] || return 1
        pg_run_query "$runner" "$db" \
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='${t}' AND column_name='created_at')" \
            || return 1
        max_created=""
        if [[ "$PG_RUN_RESULT" == "t" ]]; then
            pg_run_query "$runner" "$db" \
                "SELECT COALESCE(MAX(created_at)::text, '') FROM public.${t}" || return 1
            max_created="$PG_RUN_RESULT"
        fi
        tables_json=$(jq --arg n "$t" --argjson c "$count" --arg m "$max_created" \
            '. + {($n): {count: $c, max_created_at: (if $m == "" then null else $m end)}}' \
            <<<"$tables_json") || return 1
    done

    local migrations_json="null" max_version row_count
    pg_run_query "$runner" "$db" "SELECT to_regclass('public.refinery_schema_history') IS NOT NULL" || return 1
    if [[ "$PG_RUN_RESULT" == "t" ]]; then
        pg_run_query "$runner" "$db" "SELECT COALESCE(MAX(version), 0) FROM public.refinery_schema_history" || return 1
        max_version="$PG_RUN_RESULT"
        pg_run_query "$runner" "$db" "SELECT COUNT(*) FROM public.refinery_schema_history" || return 1
        row_count="$PG_RUN_RESULT"
        [[ "$max_version" =~ ^[0-9]+$ && "$row_count" =~ ^[0-9]+$ ]] || return 1
        migrations_json=$(jq -n --argjson v "$max_version" --argjson c "$row_count" \
            '{table: "refinery_schema_history", max_version: $v, row_count: $c}')
    fi

    local index_count fk_count trigger_count
    pg_run_query "$runner" "$db" "SELECT COUNT(*) FROM pg_indexes WHERE schemaname='public'" || return 1
    index_count="$PG_RUN_RESULT"
    pg_run_query "$runner" "$db" "SELECT COUNT(*) FROM pg_constraint WHERE contype='f'" || return 1
    fk_count="$PG_RUN_RESULT"
    pg_run_query "$runner" "$db" "SELECT COUNT(*) FROM pg_trigger WHERE NOT tgisinternal" || return 1
    trigger_count="$PG_RUN_RESULT"
    [[ "$index_count" =~ ^[0-9]+$ && "$fk_count" =~ ^[0-9]+$ && "$trigger_count" =~ ^[0-9]+$ ]] || return 1

    # shellcheck disable=SC2034  # consumed by the entrypoint run loop
    PG_COLLECT_JSON=$(jq -n \
        --argjson migrations "$migrations_json" \
        --argjson snapshot_consistent "$snapshot_consistent" \
        --argjson tables "$tables_json" \
        --argjson index_count "$index_count" \
        --argjson fk_count "$fk_count" \
        --argjson trigger_count "$trigger_count" \
        '{migrations: $migrations,
          validation: {snapshot_consistent: $snapshot_consistent, tables: $tables,
                       index_count: $index_count, fk_count: $fk_count,
                       trigger_count: $trigger_count}}')
}
