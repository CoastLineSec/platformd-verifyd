/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * verifyctl — request a presence verification from platformd-verifyd.
 *
 * `verifyctl verify [REASON]` runs the platformd-verify PAM stack for the current
 * user (touch the fingerprint reader, look at the camera, …) and prints the
 * outcome. A Varlink client of io.platformd.Verify.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <systemd/sd-json.h>
#include <systemd/sd-login.h>
#include <systemd/sd-varlink.h>

#define streq(a, b) (strcmp((a), (b)) == 0)
#define _cleanup_(f) __attribute__((cleanup(f)))
static inline void freep(void *p) { free(*(void **) p); }
#define _cleanup_free_ _cleanup_(freep)

static int cmd_verify(const char *reason) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL, *reply = NULL;
        _cleanup_free_ char *addr = NULL, *session = NULL;
        const char *dir = getenv("PLATFORMD_VERIFYD_RUNTIME"), *err = NULL;
        sd_json_variant *v;
        bool verified;
        int r;

        if (!dir || !*dir)
                dir = "/run/platformd-verifyd";
        if (asprintf(&addr, "%s/io.platformd.Verify", dir) < 0)
                return EXIT_FAILURE;
        if (sd_varlink_connect_address(&link, addr) < 0) {
                fprintf(stderr, "verifyctl: no verification service is running (%s)\n", addr);
                return EXIT_FAILURE;
        }
        (void) sd_pid_get_session(0, &session);   /* the current session, if any */

        if (sd_json_buildo(&params,
                        SD_JSON_BUILD_PAIR("sessionId", SD_JSON_BUILD_STRING(session ?: "")),
                        SD_JSON_BUILD_PAIR("reason", SD_JSON_BUILD_STRING(reason ?: "verification requested"))) < 0)
                return EXIT_FAILURE;

        printf("Prove your presence (touch the reader / look at the camera)…\n");
        r = sd_varlink_call(link, "io.platformd.Verify.VerifyUser", params, &reply, &err);
        if (r < 0) {
                fprintf(stderr, "verifyctl: call failed: %s\n", strerror(-r));
                return EXIT_FAILURE;
        }
        if (err) {
                fprintf(stderr, "verifyctl: %s\n", err);
                return EXIT_FAILURE;
        }

        v = sd_json_variant_by_key(reply, "verified");
        verified = v && sd_json_variant_boolean(v);
        v = sd_json_variant_by_key(reply, "method");
        printf("verified: %s   method: %s\n", verified ? "yes" : "no",
               v && sd_json_variant_is_string(v) ? sd_json_variant_string(v) : "-");
        return verified ? EXIT_SUCCESS : EXIT_FAILURE;
}

int main(int argc, char *argv[]) {
        const char *cmd = argc > 1 ? argv[1] : "verify";

        if (streq(cmd, "verify"))
                return cmd_verify(argc > 2 ? argv[2] : NULL);
        if (streq(cmd, "-h") || streq(cmd, "--help") || streq(cmd, "help")) {
                printf("verifyctl — request a presence verification\n\n"
                       "  verifyctl verify [REASON]   Prove the current user is present\n");
                return EXIT_SUCCESS;
        }
        fprintf(stderr, "verifyctl: unknown command '%s'\n", cmd);
        return EXIT_FAILURE;
}
