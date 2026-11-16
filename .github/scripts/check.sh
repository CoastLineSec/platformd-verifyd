#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -euo pipefail

[[ $# -ge 1 ]]
source_dir=$(cd -- "$(dirname -- "$0")/../.." && pwd)
check_dir=$(realpath -m -- "$1")
shift
[[ ! -e $check_dir/build && ! -e $check_dir/stage ]]
mkdir -p -- "$check_dir/runtime" "$check_dir/units"
chmod 0700 "$check_dir/runtime"

run() {
        env -i PATH=/usr/bin:/bin LC_ALL=C \
                CC="${CC:-cc}" \
                PKG_CONFIG_PATH="${PKG_CONFIG_PATH:-}" \
                ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
                UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
                "$@"
}

cd -- "$source_dir"
git diff --check
shellcheck .github/scripts/check.sh
actionlint .github/workflows/ci.yml
for file in man/*.xml; do
        xmllint --nonet --noout "$file"
done

run meson setup "$check_dir/build" "$source_dir" --prefix=/usr -Dwerror=true "$@"
run meson compile -C "$check_dir/build"
run meson test -C "$check_dir/build" --print-errorlogs
run meson install -C "$check_dir/build" --no-rebuild --destdir="$check_dir/stage"
test -x "$check_dir/stage/usr/libexec/platformd-verifyd"
test -f "$check_dir/stage/usr/share/varlink/io.platformd.Verify.varlink"
test -f "$check_dir/stage/usr/share/man/man8/platformd-verifyd.service.8"
(
        cd -- "$check_dir/build/man"
        for file in *.[18]; do
                groff -man -Tutf8 "$file" >/dev/null 2>"$check_dir/man-errors"
                if [[ -s $check_dir/man-errors ]]; then
                        cat "$check_dir/man-errors" >&2
                        exit 1
                fi
        done
)

unit=platformd-verifyd.service
unit_file="$check_dir/stage/usr/lib/systemd/system/$unit"
test -f "$unit_file"
[[ $(grep '^ExecStart=' "$unit_file") == 'ExecStart=/usr/libexec/platformd-verifyd' ]]
sed "s|^ExecStart=/usr/libexec/platformd-verifyd$|ExecStart=$check_dir/stage/usr/libexec/platformd-verifyd|" \
        "$unit_file" > "$check_dir/units/$unit"
env -i PATH=/usr/bin:/bin XDG_RUNTIME_DIR="$check_dir/runtime" \
        SYSTEMD_UNIT_PATH="$check_dir/units:/usr/lib/systemd/system" \
        systemd-analyze --man=no --generators=no verify "$check_dir/units/$unit"
