/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <systemd/sd-json.h>

#define VERIFY_CONTEXT_AUDIENCE_MAX 256
#define VERIFY_CONTEXT_FILE_MAX 4096

int verify_context_parse(sd_json_variant *value, sd_json_variant **ret);
