/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* verifyctl requests presence verification from platformd-verifyd. */

#include "verify-context.h"

#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <systemd/sd-json.h>
#include <systemd/sd-login.h>
#include <systemd/sd-varlink.h>

#define streq(a, b) (strcmp((a), (b)) == 0)
#define _cleanup_(f) __attribute__((cleanup(f)))
static inline void freep(void *p) { free(*(void **) p); }
#define _cleanup_free_ _cleanup_(freep)

typedef struct VerificationReply {
        sd_json_variant *result;
        char *error;
        unsigned messages;
        int status;
        bool done;
} VerificationReply;

static int on_reply(sd_varlink *link, sd_json_variant *parameters, const char *error,
                    sd_varlink_reply_flags_t flags, void *userdata) {
        VerificationReply *reply = userdata;
        sd_json_variant *message, *result, *style, *text;
        const char *s;
        int r = -EPROTO;

        if (error) {
                if (flags & SD_VARLINK_REPLY_CONTINUES)
                        goto fail;
                reply->error = strdup(error);
                if (!reply->error) {
                        r = -ENOMEM;
                        goto fail;
                }
                reply->done = true;
                return 0;
        }
        message = sd_json_variant_by_key(parameters, "message");
        result = sd_json_variant_by_key(parameters, "result");
        if (flags & SD_VARLINK_REPLY_CONTINUES) {
                if (!sd_json_variant_is_object(message) || (result && !sd_json_variant_is_null(result)) ||
                    ++reply->messages > 32)
                        goto fail;
                style = sd_json_variant_by_key(message, "style");
                text = sd_json_variant_by_key(message, "text");
                if (!sd_json_variant_is_string(style) || !sd_json_variant_is_string(text) ||
                    (!streq(sd_json_variant_string(style), "info") &&
                     !streq(sd_json_variant_string(style), "error")))
                        goto fail;
                s = sd_json_variant_string(text);
                if (strlen(s) > 1024)
                        goto fail;
                for (const unsigned char *p = (const unsigned char *) s; *p; p++)
                        if (*p < 0x20 || *p == 0x7f)
                                goto fail;
                fprintf(stderr, "PAM %s: %s\n", sd_json_variant_string(style), s);
        } else {
                if (!sd_json_variant_is_object(result) || (message && !sd_json_variant_is_null(message)))
                        goto fail;
                reply->result = sd_json_variant_ref(result);
                reply->done = true;
        }
        return 0;
fail:
        reply->status = r;
        reply->done = true;
        return 0;
}

static int verify_with_messages(sd_varlink *link, sd_json_variant *params, bool contextual,
                                sd_json_variant **ret, char **ret_error) {
        VerificationReply reply = {};
        int r;

        sd_varlink_set_userdata(link, &reply);
        r = sd_varlink_bind_reply(link, on_reply);
        if (r >= 0)
                r = sd_varlink_observe(link, contextual ? "io.platformd.Verify.VerifyUserWithContext" :
                                                          "io.platformd.Verify.VerifyUserWithMessages", params);
        while (r >= 0 && !reply.done) {
                r = sd_varlink_process(link);
                if (r == 0 && !reply.done)
                        r = sd_varlink_wait(link, UINT64_MAX);
        }
        if (r >= 0 && reply.status < 0)
                r = reply.status;
        sd_varlink_set_userdata(link, NULL);
        (void) sd_varlink_bind_reply(link, NULL);
        if (!contextual && r >= 0 && reply.error && reply.messages == 0 &&
            streq(reply.error, "org.varlink.service.MethodNotFound")) {
                const char *error = NULL;
                sd_json_variant *result = NULL;

                free(reply.error);
                reply.error = NULL;
                r = sd_varlink_call(link, "io.platformd.Verify.VerifyUser", params, &result, &error);
                if (r >= 0) {
                        reply.result = sd_json_variant_ref(result);
                        if (error && !(reply.error = strdup(error)))
                                r = -ENOMEM;
                }
        }
        *ret = reply.result;
        *ret_error = reply.error;
        return r;
}

static int context_load(const char *path, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *value = NULL;
        char buffer[VERIFY_CONTEXT_FILE_MAX + 1];
        struct stat st;
        size_t size = 0;
        int fd, r;

        fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0)
                return -errno;
        if (fstat(fd, &st) < 0) {
                r = -errno;
                goto finish;
        }
        if (!S_ISREG(st.st_mode)) {
                r = -EINVAL;
                goto finish;
        }
        while (size < sizeof buffer) {
                ssize_t n = read(fd, buffer + size, sizeof buffer - size);

                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        r = -errno;
                        goto finish;
                }
                if (n == 0)
                        break;
                size += n;
        }
        if (size > VERIFY_CONTEXT_FILE_MAX) {
                r = -E2BIG;
                goto finish;
        }
        if (memchr(buffer, 0, size)) {
                r = -EINVAL;
                goto finish;
        }
        buffer[size] = 0;
        r = sd_json_parse(buffer, 0, &value, NULL, NULL);
        if (r >= 0)
                r = verify_context_parse(value, ret);
finish:
        close(fd);
        return r;
}

static int cmd_verify(const char *reason, const char *context_path) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *context = NULL;
        _cleanup_free_ char *addr = NULL, *session = NULL;
        _cleanup_free_ char *err = NULL;
        const char *sock = getenv("PLATFORMD_VERIFY_SOCKET");
        const char *dir = getenv("PLATFORMD_VERIFYD_RUNTIME");
        sd_json_variant *v;
        bool verified;
        int r;

        if (context_path) {
                r = context_load(context_path, &context);
                if (r < 0) {
                        fprintf(stderr, "verifyctl: invalid verification context: %s\n", strerror(-r));
                        return EXIT_FAILURE;
                }
        }

        /* Accept either an explicit socket path or a runtime directory. */
        if (sock && *sock) {
                if (!(addr = strdup(sock)))
                        return EXIT_FAILURE;
        } else if (asprintf(&addr, "%s/io.platformd.Verify",
                            dir && *dir ? dir : "/run/platformd-verifyd") < 0)
                return EXIT_FAILURE;
        if (sd_varlink_connect_address(&link, addr) < 0) {
                fprintf(stderr, "verifyctl: no verification service is running (%s)\n", addr);
                return EXIT_FAILURE;
        }
        if (sd_varlink_set_relative_timeout(link, 610U * 1000000U) < 0)
                return EXIT_FAILURE;
        (void) sd_pid_get_session(0, &session);   /* the current session, if any */

        if (sd_json_buildo(&params,
                        SD_JSON_BUILD_PAIR("sessionId", SD_JSON_BUILD_STRING(session ?: "")),
                        SD_JSON_BUILD_PAIR("reason", SD_JSON_BUILD_STRING(reason ?: "verification requested"))) < 0)
                return EXIT_FAILURE;
        if (context && sd_json_variant_set_field(&params, "context", context) < 0)
                return EXIT_FAILURE;

        printf("Verify user presence with the configured factor.\n");
        fflush(stdout);
        r = verify_with_messages(link, params, context != NULL, &reply, &err);
        if (r < 0) {
                fprintf(stderr, "verifyctl: call failed: %s\n", strerror(-r));
                return EXIT_FAILURE;
        }
        if (err) {
                fprintf(stderr, "verifyctl: %s\n", err);
                return EXIT_FAILURE;
        }

        v = sd_json_variant_by_key(reply, "verified");
        if (!sd_json_variant_is_boolean(v)) {
                fprintf(stderr, "verifyctl: invalid verification result\n");
                return EXIT_FAILURE;
        }
        verified = sd_json_variant_boolean(v);
        v = sd_json_variant_by_key(reply, "method");
        printf("verified: %s   method: %s\n", verified ? "yes" : "no",
               v && sd_json_variant_is_string(v) ? sd_json_variant_string(v) : "-");
        return verified ? EXIT_SUCCESS : EXIT_FAILURE;
}

int main(int argc, char *argv[]) {
        const char *cmd = argc > 1 ? argv[1] : "verify";

        if (streq(cmd, "verify"))
                return cmd_verify(argc > 2 ? argv[2] : NULL, NULL);
        if (streq(cmd, "verify-context")) {
                if (argc < 3 || argc > 4) {
                        fputs("verifyctl: expected verify-context FILE [REASON]\n", stderr);
                        return EXIT_FAILURE;
                }
                return cmd_verify(argc > 3 ? argv[3] : NULL, argv[2]);
        }
        if (streq(cmd, "-h") || streq(cmd, "--help") || streq(cmd, "help")) {
                printf("verifyctl: request a presence verification\n\n"
                       "  verifyctl verify [REASON]                Prove the current user is present\n"
                       "  verifyctl verify-context FILE [REASON]   Bind application context to verification\n");
                return EXIT_SUCCESS;
        }
        fprintf(stderr, "verifyctl: unknown command '%s'\n", cmd);
        return EXIT_FAILURE;
}
