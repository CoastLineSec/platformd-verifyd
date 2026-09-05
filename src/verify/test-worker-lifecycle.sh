#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

exec sh "$(dirname "$0")/test-env.sh" "$@"
