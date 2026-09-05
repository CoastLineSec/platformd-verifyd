#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

test_dir=$(mktemp -d /tmp/platformd-test.XXXXXX)
test_pid=
test_group=

cleanup() {
    trap '' INT TERM
    if [ -n "$test_group" ]; then
        kill -TERM -- "-$test_group" 2>/dev/null || true
    fi
    if [ -n "$test_pid" ]; then
        kill -TERM "$test_pid" 2>/dev/null || true
        wait "$test_pid" 2>/dev/null || true
    fi
    rm -rf -- "$test_dir"
}

trap 'cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -m 700 "$test_dir/runtime" "$test_dir/data" "$test_dir/config" \
    "$test_dir/cache" "$test_dir/state" "$test_dir/tmp"

env -i \
    PATH="${PATH:-/usr/bin:/bin}" \
    LC_ALL=C \
    ASAN_OPTIONS="${ASAN_OPTIONS:-}" \
    LSAN_OPTIONS="${LSAN_OPTIONS:-}" \
    UBSAN_OPTIONS="${UBSAN_OPTIONS:-}" \
    MSAN_OPTIONS="${MSAN_OPTIONS:-}" \
    TSAN_OPTIONS="${TSAN_OPTIONS:-}" \
    MALLOC_PERTURB_="${MALLOC_PERTURB_:-0}" \
    MESON_TEST_ITERATION="${MESON_TEST_ITERATION:-1}" \
    TMPDIR="$test_dir/tmp" \
    XDG_RUNTIME_DIR="$test_dir/runtime" \
    XDG_DATA_HOME="$test_dir/data" \
    XDG_CONFIG_HOME="$test_dir/config" \
    XDG_CACHE_HOME="$test_dir/cache" \
    XDG_STATE_HOME="$test_dir/state" \
    DBUS_SYSTEM_BUS_ADDRESS="unix:path=$test_dir/no-system-bus" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=$test_dir/no-session-bus" \
    PLATFORMD_TRUSTD_STATE="$test_dir/state/trustd" \
    PLATFORMD_TRUSTD_RUNTIME="$test_dir/runtime/trustd" \
    PLATFORMD_VERIFYD_RUNTIME="$test_dir/runtime/verifyd" \
    PLATFORMD_TRUST_SOCKET="$test_dir/no-trustd" \
    PLATFORMD_VERIFY_SOCKET="$test_dir/no-verifyd" \
    PLATFORMD_ASK_PASSWORD_SOCKET="$test_dir/no-ask-password" \
    PLATFORMD_VERIFY_PAM_CONFDIR="$test_dir/no-pam" \
    TSS2_TCTI="device:$test_dir/no-tpm" \
    setsid --wait "$@" &
test_pid=$!
test_group=$test_pid
test_status=0
wait "$test_pid" || test_status=$?
test_pid=
cleanup
trap - EXIT
exit "$test_status"
