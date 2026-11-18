#!/bin/sh
# Exercise daemon startup, request validation, and worker cleanup.
set -u

if [ "${1-}" != --test-inner ]; then
        exec sh "$(dirname "$0")/test-env.sh" sh "$0" --test-inner "$@"
fi
shift

VERIFYD="$1"
VERIFYCTL="$2"
PLATFORMD_VERIFY_PAM_CONFDIR="$3"
export PLATFORMD_VERIFY_PAM_CONFDIR
PLATFORMD_VERIFYD_RUNTIME="$(mktemp -d)"
export PLATFORMD_VERIFYD_RUNTIME
PLATFORMD_VERIFY_TIMEOUT_SEC=2
export PLATFORMD_VERIFY_TIMEOUT_SEC
PLATFORMD_VERIFY_TEST_SESSION=test-session
export PLATFORMD_VERIFY_TEST_SESSION
SOCK="$PLATFORMD_VERIFYD_RUNTIME/io.platformd.Verify"
PLATFORMD_VERIFY_SOCKET="$SOCK"
export PLATFORMD_VERIFY_SOCKET

PID=
timeout 1 "$VERIFYD" --help | grep -q platformd-verifyd || exit 1
timeout 1 "$VERIFYD" --version | grep -q platformd-verifyd || exit 1
if timeout 1 "$VERIFYD" --invalid-option >/dev/null 2>&1; then
        exit 1
fi
[ ! -e "$SOCK" ] || exit 1
cleanup() {
        if [ -n "$PID" ]; then
                kill -TERM "$PID" 2>/dev/null || :
                wait "$PID" 2>/dev/null || :
        fi
        rm -rf -- "$PLATFORMD_VERIFYD_RUNTIME"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$VERIFYD" >/dev/null 2>&1 &
PID=$!

i=0
while [ ! -S "$SOCK" ] && [ "$i" -lt 100 ]; do i=$((i + 1)); sleep 0.05; done
[ -S "$SOCK" ] || { echo "FAIL: Varlink socket was not created"; exit 1; }

fail() { echo "FAIL: $*"; exit 1; }

if command -v varlinkctl >/dev/null 2>&1; then
        varlinkctl info "$SOCK" | grep -q platformd-verifyd || fail 'service information unavailable'
        normalize_idl() {
                awk '
                        { sub(/#.*/, "") }
                        /^[[:space:]]*(interface|type|method|error)[[:space:]]/ { if (s != "") print s; s = "" }
                        { gsub(/[[:space:]]/, ""); s = s $0 }
                        END { if (s != "") print s }
                ' | sort
        }
        published=$(varlinkctl introspect "$SOCK" io.platformd.Verify | normalize_idl)
        expected=$(normalize_idl < "$(dirname "$0")/io.platformd.Verify.varlink")
        [ "$published" = "$expected" ] || fail 'published interface does not match its definition'
        if R=$(varlinkctl call "$SOCK" io.platformd.Verify.VerifyUserWithMessages \
                '{"sessionId":"","reason":"non-streaming"}' 2>&1); then
                fail 'streaming method accepted a non-streaming call'
        fi
        echo "$R" | grep -q 'more' || fail "unexpected non-streaming error: $R"
        inode=$(stat -c %i "$SOCK")
        if "$VERIFYD" >/dev/null 2>&1; then
                fail 'duplicate daemon accepted'
        fi
        [ "$(stat -c %i "$SOCK")" = "$inode" ] || fail 'duplicate daemon replaced the socket'
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
