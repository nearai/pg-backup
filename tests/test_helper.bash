# Shared bats setup: source the entrypoint (guarded — the daemon does not
# start when sourced) with command stubs for tools the unit tests must not
# depend on, then relax the entrypoint's strict modes for bats internals.

repo_root() {
    cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd
}

source_entrypoint() {
    local root
    root=$(repo_root)

    # PATH stubs for tool_versions introspection (manifest_build).
    STUB_DIR="$BATS_TEST_TMPDIR/stubs"
    mkdir -p "$STUB_DIR"
    printf '#!/bin/sh\necho "pg_dump (PostgreSQL) 16.11"\n' > "$STUB_DIR/pg_dump"
    printf '#!/bin/sh\necho "aws-cli/2.32.7 Python/3.12.13"\n' > "$STUB_DIR/aws"
    chmod +x "$STUB_DIR/pg_dump" "$STUB_DIR/aws"
    PATH="$STUB_DIR:$PATH"

    # shellcheck disable=SC1091
    source "$root/entrypoint.sh"
    set +e +u
    set +o pipefail
}
