#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

if [ "${1-}" != --test-inner ]; then
    exec sh "$(dirname "$0")/test-env.sh" sh "$0" --test-inner "$@"
fi
shift

daemon=$1
module=$(realpath "$2")
client=$3
daemon_pid=
journal_pid=

cleanup() {
    for pid in "$daemon_pid" "$journal_pid"; do
        if [ -n "$pid" ]; then
            kill -TERM "$pid" 2>/dev/null || :
            wait "$pid" 2>/dev/null || :
        fi
    done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

export PLATFORMD_VERIFYD_RUNTIME="$XDG_RUNTIME_DIR/verifyd"
export PLATFORMD_VERIFY_SOCKET="$PLATFORMD_VERIFYD_RUNTIME/io.platformd.Verify"
export PLATFORMD_VERIFY_PAM_CONFDIR="$XDG_CONFIG_HOME/pam"
export PLATFORMD_VERIFY_TEST_SESSION=test-session
export PLATFORMD_VERIFY_TIMEOUT_SEC=2
mkdir -p "$PLATFORMD_VERIFY_PAM_CONFDIR"
printf 'auth required %s\n' "$module" >"$PLATFORMD_VERIFY_PAM_CONFDIR/platformd-verify"

"$daemon" --test-journal >"$TMPDIR/journal.log" 2>&1 &
journal_pid=$!
i=0
while [ ! -S "$XDG_RUNTIME_DIR/worker-journal" ] && [ "$i" -lt 100 ]; do
    i=$((i + 1))
    sleep 0.01
done
[ -S "$XDG_RUNTIME_DIR/worker-journal" ]

"$daemon" >"$TMPDIR/daemon.log" 2>&1 &
daemon_pid=$!
i=0
while [ ! -S "$PLATFORMD_VERIFY_SOCKET" ] && [ "$i" -lt 100 ]; do
    i=$((i + 1))
    sleep 0.01
done
[ -S "$PLATFORMD_VERIFY_SOCKET" ]

if ! timeout 10 "$client" verify "worker executable test" >"$TMPDIR/client.log" 2>&1 ||
   ! grep -q 'PAM info: worker-exec-conversation' "$TMPDIR/client.log" ||
   ! grep -q 'verified: yes' "$TMPDIR/client.log"; then
    cat "$TMPDIR/client.log" "$TMPDIR/daemon.log" >&2
    exit 1
fi
if ! wait "$journal_pid"; then
    cat "$TMPDIR/journal.log" >&2
    exit 1
fi
journal_pid=
printf 'OK: worker journal output survives descriptor closure\n'
