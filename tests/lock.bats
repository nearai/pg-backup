#!/usr/bin/env bats
# S3 lock JSON parsing / TTL evaluation (pure functions).

load test_helper

setup() {
    source_entrypoint
    NOW=1753660000
}

@test "lock_render: contract fields" {
    local json
    json=$(lock_render cpu01-vm "$NOW" 1800)
    [ "$(jq -r '.holder' <<<"$json")" = "cpu01-vm" ]
    [ "$(jq -r '.acquired_at' <<<"$json")" = "$NOW" ]
    [ "$(jq -r '.ttl_seconds' <<<"$json")" = "1800" ]
}

@test "lock_evaluate: fresh lock held by another member" {
    local json
    json=$(lock_render cpu02-vm "$(( NOW - 60 ))" 1800)
    run lock_evaluate "$json" "$NOW" cpu01-vm
    [ "$output" = "held" ]
}

@test "lock_evaluate: fresh lock held by self" {
    local json
    json=$(lock_render cpu01-vm "$(( NOW - 60 ))" 1800)
    run lock_evaluate "$json" "$NOW" cpu01-vm
    [ "$output" = "self" ]
}

@test "lock_evaluate: expired lock (age == ttl) is takeable" {
    local json
    json=$(lock_render cpu02-vm "$(( NOW - 1800 ))" 1800)
    run lock_evaluate "$json" "$NOW" cpu01-vm
    [ "$output" = "expired" ]
}

@test "lock_evaluate: renewal keeps a long run held" {
    # acquired_at was refreshed 300s ago by the renewal loop; still held.
    local json
    json=$(lock_render cpu02-vm "$(( NOW - 300 ))" 1800)
    run lock_evaluate "$json" "$NOW" cpu01-vm
    [ "$output" = "held" ]
}

@test "lock_evaluate: unparsable JSON -> invalid" {
    run lock_evaluate 'not-json{' "$NOW" cpu01-vm
    [ "$output" = "invalid" ]
}

@test "lock_evaluate: missing fields -> invalid" {
    run lock_evaluate '{"holder": "cpu02-vm"}' "$NOW" cpu01-vm
    [ "$output" = "invalid" ]
    run lock_evaluate '{"holder": "x", "acquired_at": "not-a-number", "ttl_seconds": 1800}' "$NOW" cpu01-vm
    [ "$output" = "invalid" ]
}

@test "lock_evaluate: empty body -> invalid" {
    run lock_evaluate "" "$NOW" cpu01-vm
    [ "$output" = "invalid" ]
}
