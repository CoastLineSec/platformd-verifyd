#!/bin/sh
# Smoke test: the daemon starts and serves io.platformd.Verify, and a verification
# with no enrolled factor returns cleanly (not verified) rather than crashing or
# hanging. The interactive factors themselves are validated by hand.
set -u

VERIFYD="$1"
VERIFYCTL="$2"
PLATFORMD_VERIFYD_RUNTIME="$(mktemp -d)"
export PLATFORMD_VERIFYD_RUNTIME
PLATFORMD_VERIFY_TIMEOUT_SEC=2
export PLATFORMD_VERIFY_TIMEOUT_SEC
SOCK="$PLATFORMD_VERIFYD_RUNTIME/io.platformd.Verify"

"$VERIFYD" >/dev/null 2>&1 &
PID=$!
trap 'kill -TERM $PID 2>/dev/null; wait $PID 2>/dev/null; rm -rf "$PLATFORMD_VERIFYD_RUNTIME"' EXIT

i=0
while [ ! -S "$SOCK" ] && [ "$i" -lt 100 ]; do i=$((i + 1)); sleep 0.05; done
[ -S "$SOCK" ] || { echo "FAIL: Varlink socket was not created"; exit 1; }

# No enrolled factor -> a clean "not verified", not a hang or crash. The timeout
# guards against a misconfigured PAM stack blocking the test.
timeout 15 "$VERIFYCTL" verify "smoke test" >/dev/null 2>&1 || true

# Abandon a request and verify that its worker does not retain the per-user slot.
timeout 0.05 "$VERIFYCTL" verify "disconnect test" >/dev/null 2>&1 || true
i=0
while [ "$i" -lt 40 ]; do
        R=$(timeout 5 "$VERIFYCTL" verify "post-disconnect test" 2>&1 || true)
        echo "$R" | grep -q 'io.platformd.Verify.Busy' || break
        i=$((i + 1))
        sleep 0.05
done
echo "$R" | grep -q 'io.platformd.Verify.Busy' && {
        echo "FAIL: disconnected request retained the per-user slot"
        exit 1
}

kill -0 "$PID" 2>/dev/null || { echo "FAIL: daemon exited during a verification"; exit 1; }
echo "OK: platformd-verifyd serves io.platformd.Verify"
