#!/usr/bin/env bats
# Cycle-owed math: schedule mode, interval mode, restart/backfill semantics.

load test_helper

setup() {
    source_entrypoint
}

epoch() {
    date -u -d "$1" +%s
}

@test "cycle_owed: before schedule time -> no" {
    run cycle_owed "$(epoch '2026-07-28T01:00:00Z')" "02:30" ""
    [ "$output" = "no" ]
}

@test "cycle_owed: exactly at schedule time, cycle not done -> yes" {
    run cycle_owed "$(epoch '2026-07-28T02:30:00Z')" "02:30" ""
    [ "$output" = "yes" ]
}

@test "cycle_owed: after schedule, cycle already done today -> no" {
    run cycle_owed "$(epoch '2026-07-28T03:00:00Z')" "02:30" "2026-07-28"
    [ "$output" = "no" ]
}

@test "cycle_owed: after schedule, last cycle was yesterday -> yes (backfill)" {
    run cycle_owed "$(epoch '2026-07-28T14:00:00Z')" "02:30" "2026-07-27"
    [ "$output" = "yes" ]
}

@test "cycle_owed: never ran before -> yes once schedule passed" {
    run cycle_owed "$(epoch '2026-07-28T23:59:00Z')" "02:30" ""
    [ "$output" = "yes" ]
}

@test "cycle_owed: manual run does not mark the cycle (cycle key unchanged)" {
    # A 01:00 manual backup leaves last_scheduled_cycle at yesterday, so the
    # 02:30 nightly is still owed.
    run cycle_owed "$(epoch '2026-07-28T02:31:00Z')" "02:30" "2026-07-27"
    [ "$output" = "yes" ]
}

@test "cycle_key_for: UTC date of the epoch" {
    run cycle_key_for "$(epoch '2026-07-28T23:59:59Z')"
    [ "$output" = "2026-07-28" ]
}

@test "schedule_passed: one minute before -> false" {
    ! schedule_passed "$(epoch '2026-07-28T02:29:00Z')" "02:30"
}

@test "schedule_passed: one minute after -> true" {
    schedule_passed "$(epoch '2026-07-28T02:31:00Z')" "02:30"
}

@test "interval_owed: no previous backup -> yes" {
    run interval_owed "$(epoch '2026-07-28T00:00:00Z')" "" 3600
    [ "$output" = "yes" ]
}

@test "interval_owed: within interval -> no" {
    local now last
    now=$(epoch '2026-07-28T01:00:00Z')
    last=$(( now - 1800 ))
    run interval_owed "$now" "$last" 3600
    [ "$output" = "no" ]
}

@test "interval_owed: interval elapsed -> yes" {
    local now last
    now=$(epoch '2026-07-28T01:00:00Z')
    last=$(( now - 3600 ))
    run interval_owed "$now" "$last" 3600
    [ "$output" = "yes" ]
}

@test "infer_env_name: prod/staging from the bucket name, else unknown" {
    run infer_env_name "nearai-postgres-backups-prod"
    [ "$output" = "prod" ]
    run infer_env_name "nearai-postgres-backups-staging"
    [ "$output" = "staging" ]
    run infer_env_name "pg-backup-e2e"
    [ "$output" = "unknown" ]
}
