#!/bin/sh
# Exercise daemon startup, request validation, and worker cleanup.
set -u

VERIFYD="$1"
VERIFYCTL="$2"
PLATFORMD_VERIFY_PAM_CONFDIR="$3"
export PLATFORMD_VERIFY_PAM_CONFDIR
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

fail() { echo "FAIL: $*"; exit 1; }

if command -v varlinkctl >/dev/null 2>&1; then
        R=$(varlinkctl call "$SOCK" io.platformd.Verify.VerifyUser \
                '{"sessionId":"","reason":1}' 2>&1 || true)
        echo "$R" | grep -q '"parameter":"reason"' \
                || fail "invalid reason was not rejected: $R"

        R=$(varlinkctl call "$SOCK" io.platformd.Verify.VerifyUser \
                '{"sessionId":"no-such-session","reason":"test"}' 2>&1 || true)
        echo "$R" | grep -q 'SessionNotEligible' \
                || fail "unknown explicit session was not rejected: $R"
fi

R=$(timeout 15 "$VERIFYCTL" verify "smoke test" 2>&1) \
        || fail "verification with the test PAM stack failed: $R"
echo "$R" | grep -q 'verified: yes' \
        || fail "verification with the test PAM stack did not succeed: $R"

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
