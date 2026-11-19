#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

process_is_live() {
    if ! read -r process_stat 2>/dev/null <"/proc/$1/stat"; then
        kill -0 "$1" 2>/dev/null
        return
    fi

    # A terminated process may remain visible until its reaper collects it.
    case "${process_stat##*) }" in
        Z\ *|X\ *) return 1 ;;
        *) return 0 ;;
    esac
}

if [ "${1-}" = --wait-for-signal ]; then
    sleep 60 &
    child_pid=$!
    trap 'kill -TERM "$child_pid" 2>/dev/null || :; wait "$child_pid" 2>/dev/null || :; exit 143' TERM
    printf '%s %s %s\n' "${XDG_RUNTIME_DIR%/runtime}" "$$" "$child_pid" >"$2"
    wait "$child_pid"
    exit 0
fi

if [ "${1-}" = --check-environment ]; then
    for name in RUNTIME_DIRECTORY NOTIFY_SOCKET LISTEN_PID LISTEN_FDS \
            LISTEN_FDNAMES WATCHDOG_PID WATCHDOG_USEC CREDENTIALS_DIRECTORY \
            ENCRYPTED_CREDENTIALS_DIRECTORY PLATFORMD_TEST_INNER \
            PLATFORMD_VERIFY_TEST_SESSION PLATFORMD_VERIFY_TIMEOUT_SEC \
            HOME SSH_AUTH_SOCK; do
        if printenv "$name" >/dev/null; then
            fail "$name was inherited"
        fi
    done

    case "$XDG_RUNTIME_DIR" in
        /tmp/platformd-test.*/runtime) ;;
        *) fail 'runtime directory is not private' ;;
    esac
    isolated_dir=${XDG_RUNTIME_DIR%/runtime}
    [ -d "$XDG_RUNTIME_DIR" ] || fail 'runtime directory is missing'
    [ "$TMPDIR" = "$isolated_dir/tmp" ] || fail 'temporary directory was inherited'
    [ "$XDG_DATA_HOME" = "$isolated_dir/data" ] || fail 'data directory was inherited'
    [ "$XDG_CONFIG_HOME" = "$isolated_dir/config" ] || fail 'configuration directory was inherited'
    [ "$XDG_CACHE_HOME" = "$isolated_dir/cache" ] || fail 'cache directory was inherited'
    [ "$XDG_STATE_HOME" = "$isolated_dir/state" ] || fail 'state directory was inherited'
    [ "$DBUS_SYSTEM_BUS_ADDRESS" = "unix:path=$isolated_dir/no-system-bus" ] || fail 'system bus was inherited'
    [ "$DBUS_SESSION_BUS_ADDRESS" = "unix:path=$isolated_dir/no-session-bus" ] || fail 'session bus was inherited'
    [ "$PLATFORMD_TRUST_SOCKET" = "$isolated_dir/no-trustd" ] || fail 'trust socket was inherited'
    [ "$PLATFORMD_VERIFY_SOCKET" = "$isolated_dir/no-verifyd" ] || fail 'verification socket was inherited'
    [ "$PLATFORMD_ASK_PASSWORD_SOCKET" = "$isolated_dir/no-ask-password" ] || fail 'password socket was inherited'
    [ "$PLATFORMD_VERIFY_PAM_CONFDIR" = "$isolated_dir/no-pam" ] || fail 'PAM configuration was inherited'
    [ "$PLATFORMD_TRUSTD_RUNTIME" = "$isolated_dir/runtime/trustd" ] || fail 'trust runtime was inherited'
    [ "$PLATFORMD_VERIFYD_RUNTIME" = "$isolated_dir/runtime/verifyd" ] || fail 'verification runtime was inherited'
    [ "$PLATFORMD_TRUSTD_STATE" = "$isolated_dir/state/trustd" ] || fail 'trust state was inherited'
    [ "$TSS2_TCTI" = "device:$isolated_dir/no-tpm" ] || fail 'TPM transport was inherited'
    printf '%s\n' "$isolated_dir"
    exit 0
fi

[ "$#" -eq 3 ] || fail 'expected daemon, client, and test PAM directory'
test_dir=$(mktemp -d /tmp/platformd-test-env.XXXXXX)
wrapper_pid=
cleanup() {
    if [ -n "$wrapper_pid" ]; then
        kill -TERM "$wrapper_pid" 2>/dev/null || :
        wait "$wrapper_pid" 2>/dev/null || :
    fi
    rm -rf -- "$test_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -m 700 "$test_dir/runtime"
touch "$test_dir/runtime/sentinel"

run_hostile() {
    env \
        PLATFORMD_TEST_INNER=1 \
        PLATFORMD_VERIFY_TEST_SESSION=inherited-session \
        PLATFORMD_VERIFY_TIMEOUT_SEC=600 \
        PLATFORMD_VERIFY_PAM_CONFDIR="$test_dir/no-pam" \
        PLATFORMD_VERIFYD_RUNTIME="$test_dir/runtime" \
        PLATFORMD_TRUSTD_RUNTIME="$test_dir/runtime" \
        PLATFORMD_TRUSTD_STATE="$test_dir/state" \
        PLATFORMD_TRUST_SOCKET="$test_dir/trust-socket" \
        PLATFORMD_VERIFY_SOCKET="$test_dir/verify-socket" \
        PLATFORMD_ASK_PASSWORD_SOCKET="$test_dir/password-socket" \
        RUNTIME_DIRECTORY="$test_dir/runtime" \
        XDG_RUNTIME_DIR="$test_dir/runtime" \
        XDG_DATA_HOME="$test_dir/data" \
        XDG_CONFIG_HOME="$test_dir/config" \
        XDG_CACHE_HOME="$test_dir/cache" \
        XDG_STATE_HOME="$test_dir/state" \
        TMPDIR="$test_dir" \
        DBUS_SYSTEM_BUS_ADDRESS="unix:path=$test_dir/system-bus" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=$test_dir/session-bus" \
        NOTIFY_SOCKET="$test_dir/notify-socket" \
        LISTEN_PID="$$" LISTEN_FDS=1 LISTEN_FDNAMES=verification \
        WATCHDOG_PID="$$" WATCHDOG_USEC=1 \
        CREDENTIALS_DIRECTORY="$test_dir/credentials" \
        ENCRYPTED_CREDENTIALS_DIRECTORY="$test_dir/encrypted-credentials" \
        SSH_AUTH_SOCK="$test_dir/ssh-agent" \
        TSS2_TCTI="device:$test_dir/tpm" \
        "$@"
}

script_dir=$(dirname "$0")
isolated_dir=$(run_hostile sh "$script_dir/test-env.sh" sh "$0" --check-environment)
[ ! -e "$isolated_dir" ] || fail 'isolated directory was not removed'

run_hostile sh "$script_dir/test-smoke.sh" "$@"
[ -f "$test_dir/runtime/sentinel" ] || fail 'inherited runtime directory was removed'
[ ! -e "$test_dir/runtime/io.platformd.Verify" ] || fail 'inherited runtime directory was used'

sh "$script_dir/test-env.sh" sh "$0" --wait-for-signal "$test_dir/ready" &
wrapper_pid=$!
i=0
while [ ! -s "$test_dir/ready" ] && [ "$i" -lt 100 ]; do
    i=$((i + 1))
    sleep 0.01
done
[ -s "$test_dir/ready" ] || fail 'signal test did not start'
read -r isolated_dir probe_pid child_pid <"$test_dir/ready"
kill -TERM "$wrapper_pid"
status=0
wait "$wrapper_pid" || status=$?
wrapper_pid=
[ "$status" -eq 143 ] || fail 'wrapper did not report termination'
[ ! -e "$isolated_dir" ] || fail 'terminated wrapper retained its directory'
if process_is_live "$probe_pid" || process_is_live "$child_pid"; then
    fail 'terminated wrapper retained a live child process'
fi
printf '%s\n' 'OK: tests discard inherited service configuration'
