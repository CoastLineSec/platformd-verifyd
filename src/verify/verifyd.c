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
 *
 * The PAM conversation blocks for as long as the factor takes — a finger on the
 * reader — so it runs in a forked worker, the way systemd-homed runs its blocking
 * work, and the reply is sent when the worker exits. Requests are serialized per
 * user and bounded globally. A worker is cancelled when its client disconnects
 * or the verification deadline expires.
 */

#include <errno.h>
#include <pwd.h>
#include <signal.h>
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
#include <sys/wait.h>

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

typedef struct Verification Verification;

static sd_event *g_event;
static Verification *g_verifications;
static unsigned g_n_verifications;
static uint64_t g_verify_timeout = 120 * 1000000ULL;

#define VERIFY_MAX_INFLIGHT 8

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
 * SubmitAuthEvent accepts it). The request is built from a variant, so every
 * field value is escaped. Best-effort: verification still stands if trustd is
 * not running. */
static void record_to_trustd(const char *user, uid_t uid, const char *session) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL, *envelope = NULL;
        _cleanup_free_ char *text = NULL;
        struct sockaddr_un sa = { .sun_family = AF_UNIX };
        struct timeval tv = { .tv_sec = 2 };
        const char *sock = getenv("PLATFORMD_TRUST_SOCKET");
        const char *dir = getenv("PLATFORMD_TRUSTD_RUNTIME");
        size_t tlen;
        int fd, len;

        /* Accept either an explicit socket path or a runtime directory. */
        if (sock && *sock)
                len = snprintf(sa.sun_path, sizeof sa.sun_path, "%s", sock);
        else
                len = snprintf(sa.sun_path, sizeof sa.sun_path, "%s/io.platformd.Trust",
                               dir && *dir ? dir : "/run/platformd-trustd");
        if (len < 0 || (size_t) len >= sizeof sa.sun_path)
                return;

        if (sd_json_buildo(&params,
                SD_JSON_BUILD_PAIR("user", SD_JSON_BUILD_STRING(user)),
                SD_JSON_BUILD_PAIR("uid", SD_JSON_BUILD_UNSIGNED(uid)),
                SD_JSON_BUILD_PAIR("pamService", SD_JSON_BUILD_STRING("platformd-verify")),
                SD_JSON_BUILD_PAIR("tty", SD_JSON_BUILD_STRING("")),
                SD_JSON_BUILD_PAIR("remoteHost", SD_JSON_BUILD_STRING("")),
                SD_JSON_BUILD_PAIR("phase", SD_JSON_BUILD_STRING("verify")),
                SD_JSON_BUILD_PAIR("declaredMethod", SD_JSON_BUILD_STRING("platformd-verify")),
                SD_JSON_BUILD_PAIR("result", SD_JSON_BUILD_STRING("success")),
                SD_JSON_BUILD_PAIR("sessionId", SD_JSON_BUILD_STRING(session ?: ""))) < 0)
                return;
        if (sd_json_buildo(&envelope,
                SD_JSON_BUILD_PAIR("method", SD_JSON_BUILD_STRING("io.platformd.Trust.SubmitAuthEvent")),
                SD_JSON_BUILD_PAIR("parameters", SD_JSON_BUILD_VARIANT(params))) < 0)
                return;
        if (sd_json_variant_format(envelope, 0, &text) < 0)
                return;

        if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0)
                return;
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        (void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        if (connect(fd, (struct sockaddr *) &sa, sizeof sa) < 0) {
                close(fd);
                return;
        }
        tlen = strlen(text);
        if (write(fd, text, tlen + 1) == (ssize_t) (tlen + 1))
                for (;;) {   /* drain the reply so trustd's write completes */
                        char buf[256];
                        ssize_t n = read(fd, buf, sizeof buf);
                        if (n <= 0 || memchr(buf, 0, (size_t) n))
                                break;
                }
        close(fd);
}

/* A verification in flight: the pending Varlink call and what the worker is
 * proving. Freed when the worker exits and the reply is sent. */
struct Verification {
        Verification *next;
        sd_varlink *link;
        sd_event_source *worker;
        sd_event_source *timeout;
        char *user;
        char *session;
        uid_t uid;
        pid_t pid;
        bool client_gone;
        bool timed_out;
};

static Verification *verification_for_uid(uid_t uid) {
        for (Verification *v = g_verifications; v; v = v->next)
                if (v->uid == uid)
                        return v;

        return NULL;
}

static void verification_free(Verification *v) {
        Verification **p;

        if (!v)
                return;

        for (p = &g_verifications; *p; p = &(*p)->next)
                if (*p == v) {
                        *p = v->next;
                        g_n_verifications--;
                        break;
                }

        sd_event_source_disable_unref(v->worker);
        sd_event_source_disable_unref(v->timeout);
        sd_varlink_unref(v->link);
        free(v->user);
        free(v->session);
        free(v);
}

static int on_verify_done(sd_event_source *s, const siginfo_t *si, void *userdata) {
        Verification *v = userdata;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
        bool verified = si->si_code == CLD_EXITED && si->si_status == 0;
        const char *outcome;

        if (v->timed_out)
                outcome = "timeout";
        else if (verified)
                outcome = "success";
        else
                outcome = "failure";

        if (verified && !v->timed_out && !v->client_gone)
                record_to_trustd(v->user, v->uid, v->session);
        sd_journal_send("MESSAGE=presence verification finished",
                        "PLATFORMD_EVENT=verify-result",
                        "PLATFORMD_VERIFY_USER=%s", v->user,
                        "PLATFORMD_VERIFY_RESULT=%s", outcome, NULL);

        if (!v->client_gone) {
                if (v->timed_out)
                        (void) sd_varlink_error(v->link, "io.platformd.Verify.VerificationTimedOut", NULL);
                else if (sd_json_buildo(&result,
                                SD_JSON_BUILD_PAIR("verified", SD_JSON_BUILD_BOOLEAN(verified)),
                                SD_JSON_BUILD_PAIR("method", SD_JSON_BUILD_STRING("platformd-verify")),
                                SD_JSON_BUILD_PAIR("realtimeUSec", SD_JSON_BUILD_UNSIGNED(now_real()))) >= 0)
                        (void) sd_varlink_reply(v->link, result);
                else
                        (void) sd_varlink_error(v->link, "io.platformd.Verify.VerificationUnsupported", NULL);
        }
        verification_free(v);
        return 0;
}

static int on_verify_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        Verification *v = userdata;

        v->timed_out = true;
        if (v->pid > 0)
                (void) kill(v->pid, SIGKILL);
        return 0;
}

static void on_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        for (Verification *v = g_verifications; v; v = v->next)
                if (v->link == link) {
                        v->client_gone = true;
                        v->link = sd_varlink_unref(v->link);
                        if (v->pid > 0)
                                (void) kill(v->pid, SIGKILL);
                        break;
                }
}

static int vl_verify_user(sd_varlink *link, sd_json_variant *parameters,
                          sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_free_ char *display = NULL, *user = NULL;
        const char *sid = "", *reason = "", *target = "";
        Verification *v;
        struct passwd *pw;
        sd_json_variant *p;
        uid_t peer;
        pid_t pid;

        /* The user is the caller's own. Copy the name out of getpwuid()'s static
         * buffer up front. */
        if (sd_varlink_get_peer_uid(link, &peer) < 0 || !(pw = getpwuid(peer)) ||
            !(user = strdup(pw->pw_name)))
                return sd_varlink_error(link, "io.platformd.Verify.PermissionDenied", NULL);

        if (verification_for_uid(peer) || g_n_verifications >= VERIFY_MAX_INFLIGHT)
                return sd_varlink_error(link, "io.platformd.Verify.Busy", NULL);

        if ((p = sd_json_variant_by_key(parameters, "sessionId")) && sd_json_variant_is_string(p))
                sid = sd_json_variant_string(p);
        if ((p = sd_json_variant_by_key(parameters, "reason")) && sd_json_variant_is_string(p))
                reason = sd_json_variant_string(p);

        /* Refresh the named session only if it is the caller's; else their display
         * session. Without any resolvable session the verification would refresh
         * nothing — decline up front rather than run a pointless authentication. */
        if (*sid) {
                uid_t su;
                if (sd_session_get_uid(sid, &su) >= 0 && su == peer)
                        target = sid;
        }
        if (!*target && sd_uid_get_display(peer, &display) >= 0)
                target = display;
        if (!target || !*target)
                return sd_varlink_error(link, "io.platformd.Verify.NoSession", NULL);

        sd_journal_send("MESSAGE=presence verification requested",
                        "PLATFORMD_EVENT=verify-request",
                        "PLATFORMD_VERIFY_USER=%s", user,
                        "PLATFORMD_VERIFY_REASON=%s", reason, NULL);

        /* The worker drives the platformd-verify PAM stack; its exit status
         * carries the outcome. The event loop stays live throughout. */
        pid = fork();
        if (pid < 0)
                return sd_varlink_error(link, "io.platformd.Verify.VerificationUnsupported", NULL);
        if (pid == 0) {
                struct pam_conv conv = { conv_fn, NULL };
                pam_handle_t *pamh = NULL;
                sigset_t unblock;
                int rc;

                sigfillset(&unblock);
                sigprocmask(SIG_UNBLOCK, &unblock, NULL);
                if (pam_start("platformd-verify", user, &conv, &pamh) != PAM_SUCCESS)
                        _exit(2);
                rc = pam_authenticate(pamh, 0);
                (void) pam_end(pamh, rc);
                _exit(rc == PAM_SUCCESS ? 0 : 1);
        }

        if (!(v = calloc(1, sizeof *v))) {
                kill(pid, SIGKILL);
                (void) waitpid(pid, NULL, 0);
                return -ENOMEM;
        }
        v->link = sd_varlink_ref(link);
        v->uid = peer;
        v->pid = pid;
        v->user = user;
        user = NULL;
        v->session = strdup(target);
        if (!v->session ||
            sd_event_add_child(g_event, &v->worker, pid, WEXITED, on_verify_done, v) < 0 ||
            sd_event_add_time_relative(g_event, &v->timeout, CLOCK_BOOTTIME,
                                       g_verify_timeout, 0, on_verify_timeout, v) < 0) {
                kill(pid, SIGKILL);
                (void) waitpid(pid, NULL, 0);
                verification_free(v);
                return sd_varlink_error(link, "io.platformd.Verify.VerificationUnsupported", NULL);
        }
        v->next = g_verifications;
        g_verifications = v;
        g_n_verifications++;
        return 0;   /* the reply is sent when the worker exits */
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

        if ((r = sd_varlink_server_bind_method(server, "io.platformd.Verify.VerifyUser", vl_verify_user)) < 0 ||
            (r = sd_varlink_server_bind_disconnect(server, on_disconnect)) < 0)
                return r;
        (void) unlink(addr);   /* clear a stale socket from a prior run */
        if ((r = sd_varlink_server_listen_address(server, addr, 0666)) < 0)
                return r;
        return sd_varlink_server_attach_event(server, event, 0);
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        sigset_t ss;
        const char *timeout;
        int r;

        if ((r = sd_event_default(&event)) < 0) {
                sd_journal_print(LOG_ERR, "sd_event_default: %s", strerror(-r));
                return EXIT_FAILURE;
        }
        g_event = event;
        timeout = getenv("PLATFORMD_VERIFY_TIMEOUT_SEC");
        if (timeout && *timeout) {
                char *end = NULL;
                unsigned long seconds;

                errno = 0;
                seconds = strtoul(timeout, &end, 10);
                if (errno == 0 && end && *end == 0 && seconds > 0 && seconds <= 600)
                        g_verify_timeout = seconds * 1000000ULL;
        }
        sigemptyset(&ss);
        sigaddset(&ss, SIGTERM);
        sigaddset(&ss, SIGINT);
        sigaddset(&ss, SIGCHLD);   /* required for tracking the worker */
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

        while (g_verifications) {
                Verification *v = g_verifications;

                if (v->pid > 0)
                        (void) kill(v->pid, SIGKILL);
                (void) waitpid(v->pid, NULL, 0);
                verification_free(v);
        }
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
