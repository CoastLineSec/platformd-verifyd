/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * platformd-verifyd — user-presence verification service.
 *
 * Answers one question over Varlink (io.platformd.Verify): "prove the calling
 * user is present, now." It runs the platformd-verify PAM stack — whatever
 * factors the administrator configured (fingerprint, face, security key,
 * password) — and, on success, records the verification with platformd-trustd so
 * the session's freshness reflects it. The user is always the caller's own,
 * derived from the peer credentials; a process can only verify itself.
 *
 * It owns the authentication: it drives PAM as root and reports the result
 * directly, so a step-up is one call, not a chain through polkit and a PAM module
 * smuggled into someone else's stack.
 */

#include <errno.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#include <security/pam_appl.h>

#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-json.h>
#include <systemd/sd-login.h>
#include <systemd/sd-varlink.h>

#define streq(a, b) (strcmp((a), (b)) == 0)
#define _cleanup_(f) __attribute__((cleanup(f)))
static inline void freep(void *p) { free(*(void **) p); }
#define _cleanup_free_ _cleanup_(freep)

static uint64_t now_real(void) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        return (uint64_t) ts.tv_sec * 1000000 + (uint64_t) ts.tv_nsec / 1000;
}

/* Agent-free PAM conversation: hardware factors (fingerprint, face) drive their
 * own device and speak only in informational messages, which need no answer.
 * Prompts that need typed input (a password) cannot be served without a UI agent
 * and fail here — such factors need the prompt agent, a defined next step. */
static int conv_fn(int num_msg, const struct pam_message **msg,
                   struct pam_response **resp, void *appdata) {
        struct pam_response *r;

        if (num_msg <= 0)
                return PAM_CONV_ERR;
        if (!(r = calloc((size_t) num_msg, sizeof *r)))
                return PAM_BUF_ERR;
        for (int i = 0; i < num_msg; i++)
                switch (msg[i]->msg_style) {
                case PAM_TEXT_INFO:
                case PAM_ERROR_MSG:
                        sd_journal_print(LOG_INFO, "pam: %s", msg[i]->msg ?: "");
                        break;   /* informational — no response */
                default:         /* PAM_PROMPT_ECHO_OFF/ON — needs an agent */
                        free(r);
                        return PAM_CONV_ERR;
                }
        *resp = r;
        return PAM_SUCCESS;
}

/* Record a successful verification with the trust authority over its Varlink
 * socket, as a raw exchange (verifyd runs as root, so the root-gated
 * SubmitAuthEvent accepts it). Best-effort: verification still stands if trustd
 * is not running. */
static void record_to_trustd(const char *user, uid_t uid, const char *session) {
        struct sockaddr_un sa = { .sun_family = AF_UNIX };
        struct timeval tv = { .tv_sec = 2 };
        const char *sock;
        char req[512];
        int fd, len;

        sock = getenv("PLATFORMD_TRUST_SOCKET");
        if (!sock || !*sock)
                sock = "/run/platformd-trustd/io.platformd.Trust";
        strncpy(sa.sun_path, sock, sizeof sa.sun_path - 1);
        if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0)
                return;
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        (void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        if (connect(fd, (struct sockaddr *) &sa, sizeof sa) < 0) {
                close(fd);
                return;
        }
        len = snprintf(req, sizeof req,
                "{\"method\":\"io.platformd.Trust.SubmitAuthEvent\",\"parameters\":{"
                "\"user\":\"%s\",\"uid\":%u,\"pamService\":\"platformd-verify\",\"tty\":\"\","
                "\"remoteHost\":\"\",\"phase\":\"verify\",\"declaredMethod\":\"platformd-verify\","
                "\"result\":\"success\",\"sessionId\":\"%s\"}}",
                user, (unsigned) uid, session);
        if (len > 0 && len < (int) sizeof req && write(fd, req, (size_t) len + 1) == (ssize_t) len + 1)
                for (;;) {   /* drain the reply so trustd's write completes */
                        char buf[256];
                        ssize_t n = read(fd, buf, sizeof buf);
                        if (n <= 0 || memchr(buf, 0, (size_t) n))
                                break;
                }
        close(fd);
}

static int vl_verify_user(sd_varlink *link, sd_json_variant *parameters,
                          sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
        _cleanup_free_ char *display = NULL, *user = NULL;
        struct pam_conv conv = { conv_fn, NULL };
        pam_handle_t *pamh = NULL;
        const char *sid = "", *reason = "", *target = "";
        struct passwd *pw;
        sd_json_variant *p;
        uid_t peer;
        bool verified;
        int r, rc;

        /* The user is the caller's own. Copy the name out of getpwuid()'s static
         * buffer before PAM runs, since PAM may call getpw* itself and clobber it. */
        if (sd_varlink_get_peer_uid(link, &peer) < 0 || !(pw = getpwuid(peer)) ||
            !(user = strdup(pw->pw_name)))
                return sd_varlink_error(link, "io.platformd.Verify.PermissionDenied", NULL);

        if ((p = sd_json_variant_by_key(parameters, "sessionId")) && sd_json_variant_is_string(p))
                sid = sd_json_variant_string(p);
        if ((p = sd_json_variant_by_key(parameters, "reason")) && sd_json_variant_is_string(p))
                reason = sd_json_variant_string(p);

        /* Refresh the named session only if it is the caller's; else their display
         * session. verifyd resolves this so trustd always gets a valid session. */
        if (*sid) {
                uid_t su;
                if (sd_session_get_uid(sid, &su) >= 0 && su == peer)
                        target = sid;
        }
        if (!*target && sd_uid_get_display(peer, &display) >= 0)
                target = display;

        sd_journal_send("MESSAGE=presence verification requested",
                        "PLATFORMD_EVENT=verify-request",
                        "PLATFORMD_VERIFY_USER=%s", user,
                        "PLATFORMD_VERIFY_REASON=%s", reason, NULL);

        /* Drive the platformd-verify PAM stack. Note: pam_authenticate is
         * synchronous and blocks the event loop while the factor completes —
         * acceptable for one verification at a time; making it async is a later
         * hardening. */
        r = pam_start("platformd-verify", user, &conv, &pamh);
        if (r != PAM_SUCCESS)
                return sd_varlink_error(link, "io.platformd.Verify.VerificationUnsupported", NULL);
        rc = pam_authenticate(pamh, 0);
        (void) pam_end(pamh, rc);
        verified = rc == PAM_SUCCESS;

        if (verified)
                record_to_trustd(user, peer, target);
        sd_journal_send("MESSAGE=presence verification %s", verified ? "succeeded" : "declined",
                        "PLATFORMD_EVENT=verify-result",
                        "PLATFORMD_VERIFY_USER=%s", user,
                        "PLATFORMD_VERIFY_RESULT=%s", verified ? "success" : "failure", NULL);

        r = sd_json_buildo(&result,
                SD_JSON_BUILD_PAIR("verified", SD_JSON_BUILD_BOOLEAN(verified)),
                SD_JSON_BUILD_PAIR("method", SD_JSON_BUILD_STRING("platformd-verify")),
                SD_JSON_BUILD_PAIR("realtimeUSec", SD_JSON_BUILD_UNSIGNED(now_real())));
        if (r < 0)
                return r;
        return sd_varlink_reply(link, result);
}

static int setup_varlink(sd_varlink_server *server, sd_event *event) {
        _cleanup_free_ char *addr = NULL;
        const char *dir;
        int r;

        dir = getenv("RUNTIME_DIRECTORY");
        if (!dir || !*dir)
                dir = getenv("PLATFORMD_VERIFYD_RUNTIME");
        if (!dir || !*dir)
                dir = "/run/platformd-verifyd";
        (void) mkdir(dir, 0755);
        if (asprintf(&addr, "%s/io.platformd.Verify", dir) < 0)
                return -ENOMEM;

        if ((r = sd_varlink_server_bind_method(server, "io.platformd.Verify.VerifyUser", vl_verify_user)) < 0)
                return r;
        if ((r = sd_varlink_server_listen_address(server, addr, 0666)) < 0)
                return r;
        return sd_varlink_server_attach_event(server, event, 0);
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        sigset_t ss;
        int r;

        if ((r = sd_event_default(&event)) < 0) {
                sd_journal_print(LOG_ERR, "sd_event_default: %s", strerror(-r));
                return EXIT_FAILURE;
        }
        sigemptyset(&ss);
        sigaddset(&ss, SIGTERM);
        sigaddset(&ss, SIGINT);
        sigprocmask(SIG_BLOCK, &ss, NULL);
        (void) sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
        (void) sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);

        if ((r = sd_varlink_server_new(&server, 0)) < 0) {
                sd_journal_print(LOG_ERR, "sd_varlink_server_new: %s", strerror(-r));
                return EXIT_FAILURE;
        }
        (void) sd_varlink_server_set_description(server, "platformd-verifyd");
        if ((r = setup_varlink(server, event)) < 0) {
                sd_journal_print(LOG_ERR, "setup_varlink: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        sd_notify(false, "READY=1\n"
                         "STATUS=platformd-verifyd: ready to verify user presence");
        sd_journal_print(LOG_INFO, "platformd-verifyd started");

        r = sd_event_loop(event);
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
