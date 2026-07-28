#!/usr/bin/env bats
# Sanitized stderr classification: whitelisted classes and counts only —
# the summary must never contain the stderr content itself.

load test_helper

setup() {
    source_entrypoint
}

@test "classify: connection errors" {
    run stderr_classify_line 'pg_dump: error: could not connect to server: Connection refused'
    [ "$output" = "connection" ]
    run stderr_classify_line 'server closed the connection unexpectedly'
    [ "$output" = "connection" ]
}

@test "classify: auth errors" {
    run stderr_classify_line 'FATAL:  password authentication failed for user "postgres"'
    [ "$output" = "auth" ]
}

@test "classify: permission errors" {
    run stderr_classify_line 'ERROR:  permission denied for table users'
    [ "$output" = "permission" ]
}

@test "classify: already exists" {
    run stderr_classify_line 'ERROR:  role "postgres" already exists'
    [ "$output" = "already_exists" ]
}

@test "classify: missing object" {
    run stderr_classify_line 'ERROR:  relation "public.gone" does not exist'
    [ "$output" = "missing_object" ]
}

@test "classify: disk errors" {
    run stderr_classify_line 'could not write to file "base/16384/2601": No space left on device'
    [ "$output" = "disk" ]
}

@test "classify: snapshot errors" {
    run stderr_classify_line 'ERROR:  invalid snapshot identifier: "00000003-000001AB-1"'
    [ "$output" = "snapshot" ]
}

@test "classify: aws errors" {
    run stderr_classify_line 'upload failed: - to s3://bucket/key An error occurred (AccessDenied)'
    [ "$output" = "aws" ]
}

@test "classify: openssl decrypt errors" {
    run stderr_classify_line 'bad decrypt 140234:error:1C800064'
    [ "$output" = "decrypt" ]
}

@test "classify: unknown lines fall through to other" {
    run stderr_classify_line 'some totally novel failure text'
    [ "$output" = "other" ]
}

@test "summarize: empty or missing file -> 0 lines" {
    run stderr_summarize "$BATS_TEST_TMPDIR/does-not-exist"
    [ "$output" = "0 lines" ]
    : > "$BATS_TEST_TMPDIR/empty"
    run stderr_summarize "$BATS_TEST_TMPDIR/empty"
    [ "$output" = "0 lines" ]
}

@test "summarize: counts per class, no content leaked" {
    local f="$BATS_TEST_TMPDIR/stderr"
    {
        echo 'pg_dump: error: could not connect to server: Connection refused'
        echo 'server closed the connection unexpectedly'
        echo 'SECRET-ROW-VALUE jean.dupont@example.ch mysterious failure'
        echo 'ERROR:  permission denied for table users'
    } > "$f"
    run stderr_summarize "$f"
    [ "$output" = "4 lines (connection:2 permission:1 other:1)" ]
    [[ "$output" != *SECRET-ROW-VALUE* ]]
    [[ "$output" != *jean.dupont* ]]
}

@test "count_errors: benign 'already exists' excluded" {
    local f="$BATS_TEST_TMPDIR/globals.stderr"
    {
        echo 'ERROR:  role "postgres" already exists'
        echo 'ERROR:  role "datadog" already exists'
        echo 'ERROR:  permission denied to create role'
        echo 'NOTICE: something harmless'
    } > "$f"
    run stderr_count_errors "$f" "already exists"
    [ "$output" = "1" ]
}

@test "count_errors: no benign pattern counts all errors" {
    local f="$BATS_TEST_TMPDIR/all.stderr"
    {
        echo 'ERROR:  one'
        echo 'FATAL:  two'
        echo 'harmless line'
    } > "$f"
    run stderr_count_errors "$f"
    [ "$output" = "2" ]
}
