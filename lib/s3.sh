#!/usr/bin/env bash
# S3 helper functions. All keys are bucket-relative (the layout uses explicit
# backups/, control/ and restore-reports/ prefixes). $S3_BUCKET is set by the
# entrypoint from BACKUP_S3_BUCKET or RESTORE_S3_BUCKET depending on mode.

s3_put_stream() {
    local s3_key="$1"
    local expected_size="${2:-}"

    if [[ -n "$expected_size" ]]; then
        aws s3 cp - "s3://${S3_BUCKET}/${s3_key}" --expected-size "$expected_size" --quiet
    else
        aws s3 cp - "s3://${S3_BUCKET}/${s3_key}" --quiet
    fi
}

s3_put_file() {
    local local_path="$1"
    local s3_key="$2"

    aws s3 cp "$local_path" "s3://${S3_BUCKET}/${s3_key}" --quiet
}

s3_get_file() {
    local s3_key="$1"
    local local_path="$2"

    aws s3 cp "s3://${S3_BUCKET}/${s3_key}" "$local_path" --quiet
}

s3_get_stdout() {
    local s3_key="$1"

    aws s3 cp "s3://${S3_BUCKET}/${s3_key}" - --quiet
}

s3_exists() {
    local s3_key="$1"

    aws s3api head-object \
        --bucket "$S3_BUCKET" \
        --key "$s3_key" \
        >/dev/null 2>&1
}

# Plain DeleteObject. On a versioned bucket this writes a delete marker;
# object versions survive (the writer principal cannot delete versions).
s3_delete() {
    local s3_key="$1"

    aws s3 rm "s3://${S3_BUCKET}/${s3_key}" --quiet
}

# List object keys under a prefix, one per line, lexicographically sorted.
s3_list_keys() {
    local prefix="$1"

    aws s3api list-objects-v2 \
        --bucket "$S3_BUCKET" \
        --prefix "$prefix" \
        --query 'Contents[].Key' \
        --output text 2>/dev/null \
        | tr '\t' '\n' | grep -v '^None$' | sort || true
}
