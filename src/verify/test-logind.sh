#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

command -v dbus-run-session >/dev/null 2>&1 || exit 77
exec sh "$(dirname "$0")/test-env.sh" dbus-run-session -- "$@"
