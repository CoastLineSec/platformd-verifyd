/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "verify-util.h"

#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <security/pam_appl.h>

#include <systemd/sd-bus.h>
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

#define VERIFY_MAX_INFLIGHT 8
#define TRUST_SUBMIT_TIMEOUT_USEC (2U * 1000000U)

enum {
        WORKER_AUTH_FAILED = 1,
        WORKER_SETUP_FAILED = 2,
        WORKER_PROMPT_UNAVAILABLE = 10,
        WORKER_PROMPT_TIMED_OUT = 11,
        WORKER_PROMPT_CANCELLED = 12,
};

typedef struct Verification Verification;
typedef struct TrustSubmission TrustSubmission;

struct Verification {
        Verification *next;
        sd_varlink *link;
        sd_event_source *worker;
        sd_event_source *timeout;
        sd_bus_slot *properties_slot;
        sd_bus_slot *removed_slot;
        char *user;
        char *session;
        char *session_path;
        uid_t uid;
        pid_t pid;
        bool client_gone;
        bool timed_out;
        bool cancelled;
};

struct TrustSubmission {
        TrustSubmission *next;
        sd_varlink *link;
        sd_event_source *timeout;
};

static sd_event *g_event;
static sd_bus *g_bus;
static Verification *g_verifications;
static TrustSubmission *g_submissions;
static unsigned g_n_verifications;
static uint64_t g_verify_timeout = 120U * 1000000U;

#ifdef VERIFYD_TESTING
static const char *test_session_id(void) {
        const char *session = getenv("PLATFORMD_VERIFY_TEST_SESSION");

        return session && *session ? session : NULL;
}
#endif

static uint64_t now_real(void) {
        struct timespec ts;

        clock_gettime(CLOCK_REALTIME, &ts);
        return (uint64_t) ts.tv_sec * 1000000U + (uint64_t) ts.tv_nsec / 1000U;
}

static void strv_free(char **l) {
        if (!l)
                return;

        for (char **p = l; *p; p++)
                free(*p);
        free(l);
}

static int session_path(const char *session, char **ret) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *path;
        int r;

        *ret = NULL;
        if (!g_bus)
                return -ENOTCONN;

        r = sd_bus_call_method(
                        g_bus,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "GetSession",
                        NULL,
                        &reply,
                        "s",
                        session);
        if (r < 0)
                return r;
        r = sd_bus_message_read(reply, "o", &path);
        if (r < 0)
                return r;
        *ret = strdup(path);
        return *ret ? 0 : -ENOMEM;
}

static int session_eligible(const char *session, uid_t uid, char **ret_path) {
        _cleanup_free_ char *class = NULL, *path = NULL;
        uid_t owner;
        int active, locked, remote, r;

        if (!session || !*session)
                return -EINVAL;
#ifdef VERIFYD_TESTING
        const char *test_session = test_session_id();

        if (test_session && streq(session, test_session)) {
                if (ret_path) {
                        *ret_path = strdup("/org/freedesktop/login1/session/platformd_test");
                        if (!*ret_path)
                                return -ENOMEM;
                }
                return 1;
        }
#endif
        if (sd_session_get_uid(session, &owner) < 0 || owner != uid)
                return 0;
        if (!g_bus)
                return -ENOTCONN;
        active = sd_session_is_active(session);
        remote = sd_session_is_remote(session);
        if (active < 0 || remote < 0)
                return -EIO;
        if (active == 0 || remote != 0)
                return 0;
        if (sd_session_get_class(session, &class) < 0)
                return -EIO;
        if (!verify_session_class_allowed(class))
                return 0;
        if ((r = session_path(session, &path)) < 0)
                return r;
        r = sd_bus_get_property_trivial(
                        g_bus,
                        "org.freedesktop.login1",
                        path,
                        "org.freedesktop.login1.Session",
                        "LockedHint",
                        NULL,
                        'b',
                        &locked);
        if (r < 0)
                return r;
        if (locked)
                return 0;

        if (ret_path)
                *ret_path = path, path = NULL;
        return 1;
}

static int select_session(
                uid_t uid,
                pid_t peer_pid,
                const char *requested,
                char **ret_session,
                char **ret_path) {

        _cleanup_free_ char *peer_session = NULL, *selected = NULL, *path = NULL;
        char **sessions = NULL;
        unsigned eligible = 0;
        int n, r;

        *ret_session = NULL;
        *ret_path = NULL;

#ifdef VERIFYD_TESTING
        const char *test_session = test_session_id();

        if (test_session &&
            (!requested || !*requested || streq(requested, test_session))) {
                *ret_session = strdup(test_session);
                *ret_path = strdup("/org/freedesktop/login1/session/platformd_test");
                if (!*ret_session || !*ret_path) {
                        free(*ret_session);
                        free(*ret_path);
                        *ret_session = *ret_path = NULL;
                        return -ENOMEM;
                }
                return 0;
        }
#endif

        if (requested && *requested) {
                r = session_eligible(requested, uid, &path);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EACCES;
                selected = strdup(requested);
                if (!selected)
                        return -ENOMEM;
                *ret_session = selected;
                selected = NULL;
                *ret_path = path;
                path = NULL;
                return 0;
        }

        if (peer_pid > 0 && sd_pid_get_session(peer_pid, &peer_session) >= 0) {
                r = session_eligible(peer_session, uid, &path);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EACCES;
                *ret_session = peer_session;
                peer_session = NULL;
                *ret_path = path;
                path = NULL;
                return 0;
        }

        n = sd_uid_get_sessions(uid, false, &sessions);
        if (n < 0)
                return n;
        for (int i = 0; i < n; i++) {
                _cleanup_free_ char *candidate_path = NULL;

                r = session_eligible(sessions[i], uid, &candidate_path);
                if (r < 0) {
                        strv_free(sessions);
                        return r;
                }
                if (r == 0)
                        continue;
                eligible++;
                if (eligible == 1) {
                        selected = strdup(sessions[i]);
                        path = candidate_path;
                        candidate_path = NULL;
                        if (!selected) {
                                strv_free(sessions);
                                return -ENOMEM;
                        }
                }
        }
        strv_free(sessions);

        if (eligible == 0)
                return -ENXIO;
        if (eligible > 1)
                return -ENOTUNIQ;

        *ret_session = selected;
        selected = NULL;
        *ret_path = path;
        path = NULL;
        return 0;
}

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
        sd_bus_slot_unref(v->properties_slot);
        sd_bus_slot_unref(v->removed_slot);
        sd_varlink_unref(v->link);
        free(v->user);
        free(v->session);
        free(v->session_path);
        free(v);
}

static void verification_cancel(Verification *v) {
        if (!v || v->cancelled)
                return;

        v->cancelled = true;
        if (v->pid > 0)
                (void) kill(v->pid, SIGKILL);
}

static int on_session_properties(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Verification *v = userdata;

        if (session_eligible(v->session, v->uid, NULL) != 1)
                verification_cancel(v);
        return 0;
}

static int on_session_removed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Verification *v = userdata;
        const char *id, *path;

        if (sd_bus_message_read(message, "so", &id, &path) >= 0 &&
            (streq(id, v->session) || streq(path, v->session_path)))
                verification_cancel(v);
        return 0;
}

static void trust_submission_free(TrustSubmission *submission) {
        TrustSubmission **p;

        if (!submission)
                return;

        for (p = &g_submissions; *p; p = &(*p)->next)
                if (*p == submission) {
                        *p = submission->next;
                        break;
                }
        sd_event_source_disable_unref(submission->timeout);
        sd_varlink_unref(submission->link);
        free(submission);
}

static int on_trust_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        TrustSubmission *submission = userdata;

        if (error_id)
                sd_journal_print(LOG_DEBUG, "authentication event was not recorded: %s", error_id);
        trust_submission_free(submission);
        return 0;
}

static int on_trust_timeout(sd_event_source *source, uint64_t usec, void *userdata) {
        trust_submission_free(userdata);
        return 0;
}

static void submit_to_trustd(const char *user, uid_t uid, const char *session) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        TrustSubmission *submission;
        const char *address;

        address = getenv("PLATFORMD_TRUST_SOCKET");
        if (!address || !*address)
                address = "/run/platformd-trustd/io.platformd.Trust";

        submission = calloc(1, sizeof *submission);
        if (!submission)
                return;
        if (sd_json_buildo(&parameters,
                        SD_JSON_BUILD_PAIR("user", SD_JSON_BUILD_STRING(user)),
                        SD_JSON_BUILD_PAIR("uid", SD_JSON_BUILD_UNSIGNED(uid)),
                        SD_JSON_BUILD_PAIR("pamService", SD_JSON_BUILD_STRING("platformd-verify")),
                        SD_JSON_BUILD_PAIR("tty", SD_JSON_BUILD_STRING("")),
                        SD_JSON_BUILD_PAIR("remoteHost", SD_JSON_BUILD_STRING("")),
                        SD_JSON_BUILD_PAIR("phase", SD_JSON_BUILD_STRING("verify")),
                        SD_JSON_BUILD_PAIR("declaredMethod", SD_JSON_BUILD_STRING("platformd-verify")),
                        SD_JSON_BUILD_PAIR("result", SD_JSON_BUILD_STRING("success")),
                        SD_JSON_BUILD_PAIR("sessionId", SD_JSON_BUILD_STRING(session))) < 0 ||
            sd_varlink_connect_address(&submission->link, address) < 0) {
                trust_submission_free(submission);
                return;
        }

        (void) sd_varlink_set_userdata(submission->link, submission);
        if (sd_varlink_bind_reply(submission->link, on_trust_reply) < 0 ||
            sd_varlink_attach_event(submission->link, g_event, SD_EVENT_PRIORITY_NORMAL) < 0 ||
            sd_event_add_time_relative(
                            g_event,
                            &submission->timeout,
                            CLOCK_BOOTTIME,
                            TRUST_SUBMIT_TIMEOUT_USEC,
                            0,
                            on_trust_timeout,
                            submission) < 0 ||
            sd_varlink_invoke(
                            submission->link,
                            "io.platformd.Trust.SubmitAuthEvent",
                            parameters) < 0) {
                trust_submission_free(submission);
                return;
        }

        submission->next = g_submissions;
        g_submissions = submission;
}

static int on_verify_done(sd_event_source *source, const siginfo_t *si, void *userdata) {
        Verification *v = userdata;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
        bool verified;
        const char *outcome;
        int status;

        status = si->si_code == CLD_EXITED ? si->si_status : WORKER_AUTH_FAILED;
        if (!v->timed_out && !v->cancelled &&
            session_eligible(v->session, v->uid, NULL) != 1)
                v->cancelled = true;
        verified = status == EXIT_SUCCESS && !v->timed_out && !v->cancelled;

        if (v->timed_out || status == WORKER_PROMPT_TIMED_OUT)
                outcome = "timeout";
        else if (v->cancelled)
                outcome = "cancelled";
        else if (status == WORKER_PROMPT_UNAVAILABLE)
                outcome = "prompt-unavailable";
        else if (verified)
                outcome = "success";
        else
                outcome = "failure";

        sd_journal_send(
                        "MESSAGE=presence verification finished",
                        "PLATFORMD_EVENT=verify-result",
                        "PLATFORMD_VERIFY_USER=%s", v->user,
                        "PLATFORMD_VERIFY_SESSION=%s", v->session,
                        "PLATFORMD_VERIFY_RESULT=%s", outcome,
                        NULL);

        if (!v->client_gone) {
                if (v->timed_out || status == WORKER_PROMPT_TIMED_OUT)
                        (void) sd_varlink_error(
                                        v->link,
                                        "io.platformd.Verify.VerificationTimedOut",
                                        NULL);
                else if (v->cancelled || status == WORKER_PROMPT_CANCELLED)
                        (void) sd_varlink_error(
                                        v->link,
                                        "io.platformd.Verify.VerificationCancelled",
                                        NULL);
                else if (status == WORKER_PROMPT_UNAVAILABLE)
                        (void) sd_varlink_error(
                                        v->link,
                                        "io.platformd.Verify.PromptUnavailable",
                                        NULL);
                else if (sd_json_buildo(
                                        &result,
                                        SD_JSON_BUILD_PAIR(
                                                        "verified",
                                                        SD_JSON_BUILD_BOOLEAN(verified)),
                                        SD_JSON_BUILD_PAIR(
                                                        "method",
                                                        SD_JSON_BUILD_STRING("platformd-verify")),
                                        SD_JSON_BUILD_PAIR(
                                                        "realtimeUSec",
                                                        SD_JSON_BUILD_UNSIGNED(now_real()))) >= 0)
                        (void) sd_varlink_reply(v->link, result);
                else
                        (void) sd_varlink_error(
                                        v->link,
                                        "io.platformd.Verify.VerificationUnsupported",
                                        NULL);
        }

        if (verified && !v->client_gone)
                submit_to_trustd(v->user, v->uid, v->session);
        verification_free(v);
        return 0;
}

static int on_verify_timeout(sd_event_source *source, uint64_t usec, void *userdata) {
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

static int worker_run(uid_t uid, const char *user, const char *reason) {
        VerifyConversationContext context = {
                .address = getenv("PLATFORMD_ASK_PASSWORD_SOCKET"),
                .reason = reason,
                .uid = uid,
                .timeout_usec = g_verify_timeout,
        };
        struct pam_conv conversation = { verify_pam_conversation, &context };
        const char *confdir;
        pam_handle_t *pamh = NULL;
        int r;

        confdir = getenv("PLATFORMD_VERIFY_PAM_CONFDIR");
        if (confdir && *confdir)
                r = pam_start_confdir("platformd-verify", user, &conversation, confdir, &pamh);
        else
                r = pam_start("platformd-verify", user, &conversation, &pamh);
        if (r != PAM_SUCCESS)
                return WORKER_SETUP_FAILED;

        r = pam_authenticate(pamh, 0);
        (void) pam_end(pamh, r);
        if (context.prompt_status == VERIFY_PROMPT_TIMED_OUT)
                return WORKER_PROMPT_TIMED_OUT;
        if (context.prompt_status == VERIFY_PROMPT_CANCELLED)
                return WORKER_PROMPT_CANCELLED;
        if (context.prompt_status == VERIFY_PROMPT_UNAVAILABLE ||
            context.prompt_status == VERIFY_PROMPT_PROTOCOL_ERROR)
                return WORKER_PROMPT_UNAVAILABLE;
        return r == PAM_SUCCESS ? EXIT_SUCCESS : WORKER_AUTH_FAILED;
}

static int prepare_monitor(Verification *v) {
        int r;

#ifdef VERIFYD_TESTING
        const char *test_session = test_session_id();

        if (test_session && streq(v->session, test_session))
                return 0;
#endif

        r = sd_bus_match_signal(
                        g_bus,
                        &v->properties_slot,
                        "org.freedesktop.login1",
                        v->session_path,
                        "org.freedesktop.DBus.Properties",
                        "PropertiesChanged",
                        on_session_properties,
                        v);
        if (r < 0)
                return r;
        r = sd_bus_match_signal(
                        g_bus,
                        &v->removed_slot,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "SessionRemoved",
                        on_session_removed,
                        v);
        if (r < 0)
                return r;
        return session_eligible(v->session, v->uid, NULL) == 1 ? 0 : -EHOSTDOWN;
}

static int vl_verify_user(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        _cleanup_free_ char *session = NULL, *session_object = NULL, *user = NULL;
        const char *requested, *reason;
        Verification *v = NULL;
        struct passwd *pw;
        sd_json_variant *p;
        uid_t peer;
        pid_t peer_pid, pid;
        int r;

        if (sd_varlink_get_peer_uid(link, &peer) < 0 ||
            sd_varlink_get_peer_pid(link, &peer_pid) < 0 ||
            !(pw = getpwuid(peer)) ||
            !(user = strdup(pw->pw_name)))
                return sd_varlink_error(link, "io.platformd.Verify.PermissionDenied", NULL);

        if (verification_for_uid(peer) || g_n_verifications >= VERIFY_MAX_INFLIGHT)
                return sd_varlink_error(link, "io.platformd.Verify.Busy", NULL);

        p = sd_json_variant_by_key(parameters, "sessionId");
        if (!p || !sd_json_variant_is_string(p))
                return sd_varlink_error_invalid_parameter_name(link, "sessionId");
        requested = sd_json_variant_string(p);
        if (!verify_text_valid(requested, VERIFY_SESSION_MAX))
                return sd_varlink_error_invalid_parameter_name(link, "sessionId");

        p = sd_json_variant_by_key(parameters, "reason");
        if (!p || !sd_json_variant_is_string(p))
                return sd_varlink_error_invalid_parameter_name(link, "reason");
        reason = sd_json_variant_string(p);
        if (!verify_text_valid(reason, VERIFY_REASON_MAX))
                return sd_varlink_error_invalid_parameter_name(link, "reason");

        r = select_session(peer, peer_pid, requested, &session, &session_object);
        if (r == -ENOTUNIQ)
                return sd_varlink_error(link, "io.platformd.Verify.AmbiguousSession", NULL);
        if (r == -EACCES)
                return sd_varlink_error(link, "io.platformd.Verify.SessionNotEligible", NULL);
        if (r < 0)
                return sd_varlink_error(link, "io.platformd.Verify.NoSession", NULL);

        v = calloc(1, sizeof *v);
        if (!v)
                return -ENOMEM;
        v->link = sd_varlink_ref(link);
        v->uid = peer;
        v->user = user;
        user = NULL;
        v->session = session;
        session = NULL;
        v->session_path = session_object;
        session_object = NULL;

        if (prepare_monitor(v) < 0) {
                verification_free(v);
                return sd_varlink_error(link, "io.platformd.Verify.SessionNotEligible", NULL);
        }

        sd_journal_send(
                        "MESSAGE=presence verification requested",
                        "PLATFORMD_EVENT=verify-request",
                        "PLATFORMD_VERIFY_USER=%s", v->user,
                        "PLATFORMD_VERIFY_SESSION=%s", v->session,
                        "PLATFORMD_VERIFY_REASON=%s", reason,
                        NULL);

        pid = fork();
        if (pid < 0) {
                verification_free(v);
                return sd_varlink_error(
                                link,
                                "io.platformd.Verify.VerificationUnsupported",
                                NULL);
        }
        if (pid == 0) {
                sigset_t unblock;

                sigfillset(&unblock);
                (void) sigprocmask(SIG_UNBLOCK, &unblock, NULL);
                _exit(worker_run(peer, v->user, reason));
        }
        v->pid = pid;

        if (sd_event_add_child(g_event, &v->worker, pid, WEXITED, on_verify_done, v) < 0 ||
            sd_event_add_time_relative(
                            g_event,
                            &v->timeout,
                            CLOCK_BOOTTIME,
                            g_verify_timeout,
                            0,
                            on_verify_timeout,
                            v) < 0) {
                (void) kill(pid, SIGKILL);
                (void) waitpid(pid, NULL, 0);
                verification_free(v);
                return sd_varlink_error(
                                link,
                                "io.platformd.Verify.VerificationUnsupported",
                                NULL);
        }

        v->next = g_verifications;
        g_verifications = v;
        g_n_verifications++;
        return 0;
}

static int setup_varlink(sd_varlink_server *server, sd_event *event) {
        _cleanup_free_ char *address = NULL;
        const char *directory;
        int r;

        directory = getenv("RUNTIME_DIRECTORY");
        if (!directory || !*directory)
                directory = getenv("PLATFORMD_VERIFYD_RUNTIME");
        if (!directory || !*directory)
                directory = "/run/platformd-verifyd";
        (void) mkdir(directory, 0755);
        if (asprintf(&address, "%s/io.platformd.Verify", directory) < 0)
                return -ENOMEM;

        r = sd_varlink_server_bind_method(
                        server,
                        "io.platformd.Verify.VerifyUser",
                        vl_verify_user);
        if (r < 0)
                return r;
        r = sd_varlink_server_bind_disconnect(server, on_disconnect);
        if (r < 0)
                return r;
        (void) unlink(address);
        r = sd_varlink_server_listen_address(server, address, 0666);
        if (r < 0)
                return r;
        return sd_varlink_server_attach_event(server, event, 0);
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        const char *timeout;
        sigset_t signals;
        int r;

        r = sd_event_default(&event);
        if (r < 0) {
                sd_journal_print(LOG_ERR, "Failed to allocate event loop: %s", strerror(-r));
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
                        g_verify_timeout = seconds * 1000000U;
        }

        sigemptyset(&signals);
        sigaddset(&signals, SIGTERM);
        sigaddset(&signals, SIGINT);
        sigaddset(&signals, SIGCHLD);
        (void) sigprocmask(SIG_BLOCK, &signals, NULL);
        (void) sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
        (void) sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);

        r = sd_bus_open_system(&bus);
        if (r >= 0)
                r = sd_bus_attach_event(bus, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0) {
                sd_journal_print(LOG_WARNING, "logind session validation is unavailable: %s",
                                 strerror(-r));
                bus = sd_bus_flush_close_unref(bus);
        }
        g_bus = bus;

        r = sd_varlink_server_new(&server, 0);
        if (r < 0) {
                sd_journal_print(LOG_ERR, "Failed to allocate Varlink server: %s", strerror(-r));
                return EXIT_FAILURE;
        }
        (void) sd_varlink_server_set_description(server, "platformd-verifyd");
        r = setup_varlink(server, event);
        if (r < 0) {
                sd_journal_print(LOG_ERR, "Failed to set up Varlink: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        sd_notify(
                        false,
                        "READY=1\n"
                        "STATUS=Ready to verify user presence");
        sd_journal_print(LOG_INFO, "platformd-verifyd started");

        r = sd_event_loop(event);

        while (g_verifications) {
                Verification *v = g_verifications;

                if (v->pid > 0)
                        (void) kill(v->pid, SIGKILL);
                (void) waitpid(v->pid, NULL, 0);
                verification_free(v);
        }
        while (g_submissions)
                trust_submission_free(g_submissions);
        g_bus = NULL;
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
