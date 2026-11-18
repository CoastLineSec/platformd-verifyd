/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "verify-context.h"

#include <errno.h>
#include <string.h>

static int digest_parse(sd_json_variant *value, char ret[65]) {
        const char *s;

        if (!sd_json_variant_is_string(value))
                return -EINVAL;
        s = sd_json_variant_string(value);
        if (strnlen(s, 65) != 64)
                return -EINVAL;
        for (size_t i = 0; i < 64; i++)
                if ((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))
                        ret[i] = s[i];
                else if (s[i] >= 'A' && s[i] <= 'F')
                        ret[i] = s[i] - 'A' + 'a';
                else
                        return -EINVAL;
        ret[64] = 0;
        return 0;
}

int verify_context_parse(sd_json_variant *value, sd_json_variant **ret) {
        static const char * const fields[] = { "challengeHex", "audience", "operationDigestHex" };
        char challenge[65], operation[65];
        sd_json_variant *audience;
        const char *s;
        unsigned seen = 0;
        size_t n;

        if (!sd_json_variant_is_object(value) || sd_json_variant_elements(value) != 6)
                return -EINVAL;
        for (size_t i = 0; i < 6; i += 2) {
                const char *key = sd_json_variant_string(sd_json_variant_by_index(value, i));
                unsigned bit = 0;

                if (!key)
                        return -EINVAL;
                for (size_t j = 0; j < sizeof fields / sizeof fields[0]; j++)
                        if (strcmp(key, fields[j]) == 0) {
                                bit = 1U << j;
                                break;
                        }
                if (!bit || (seen & bit))
                        return -EINVAL;
                seen |= bit;
        }
        if (digest_parse(sd_json_variant_by_key(value, "challengeHex"), challenge) < 0 ||
            digest_parse(sd_json_variant_by_key(value, "operationDigestHex"), operation) < 0)
                return -EINVAL;
        audience = sd_json_variant_by_key(value, "audience");
        if (!sd_json_variant_is_string(audience))
                return -EINVAL;
        s = sd_json_variant_string(audience);
        n = strnlen(s, VERIFY_CONTEXT_AUDIENCE_MAX + 1);
        if (n == 0 || n > VERIFY_CONTEXT_AUDIENCE_MAX)
                return -EINVAL;
        for (size_t i = 0; i < n; i++)
                if ((unsigned char) s[i] < 0x20 || (unsigned char) s[i] > 0x7e)
                        return -EINVAL;
        return sd_json_buildo(ret,
                             SD_JSON_BUILD_PAIR_STRING("challengeHex", challenge),
                             SD_JSON_BUILD_PAIR_STRING("audience", s),
                             SD_JSON_BUILD_PAIR_STRING("operationDigestHex", operation));
}
