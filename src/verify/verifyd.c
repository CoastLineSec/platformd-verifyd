/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "verify-util.h"
#include "verify-worker.h"
#include "varlink-interface.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
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
        sd_bus_slot *validation_slot;
        char *user;
        char *reason;
        char *session;
        char *session_path;
        char **candidate_sessions;
        char *candidate_path;
        size_t candidate_index;
        uid_t uid;
        pid_t pid;
        uint64_t deadline_usec;
        int result_status;
        bool worker_finished;
        bool client_gone;
        bool timed_out;
        bool cancelled;
        bool selecting;
};

struct TrustSubmission {
        TrustSubmission *next;
        sd_varlink *link;
        sd_event_source *timeout;
};

static sd_event *g_event;
static sd_bus *g_bus;
static int g_listener_lock = -1;
static Verification *g_verifications;
static TrustSubmission *g_submissions;
static unsigned g_n_verifications;
static uint64_t g_verify_timeout = 120U * 1000000U;
static void verification_complete(Verification *verification);
static int verification_launch(Verification *verification);
static int verification_validate(Verification *verification);
static int verification_select_next(Verification *verification);

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

static bool verification_expired(Verification *v) {
        struct timespec ts;

        if (clock_gettime(CLOCK_BOOTTIME, &ts) < 0)
                return true;
        return (uint64_t) ts.tv_sec * 1000000U + ts.tv_nsec / 1000U >= v->deadline_usec;
}

static void strv_free(char **l) {
        if (!l)
                return;

        for (char **p = l; *p; p++)
                free(*p);
        free(l);
}


static int session_eligible(const char *session, uid_t uid, char **ret_path) {
        _cleanup_free_ char *class = NULL, *path = NULL;
        uid_t owner;
        int active, remote, r;

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
        if (ret_path) {
                r = sd_bus_path_encode("/org/freedesktop/login1/session", session, &path);
                if (r < 0)
                        return r;
                *ret_path = path;
                path = NULL;
        }
        return 1;
}

static int select_session(
                uid_t uid,
                pid_t peer_pid,
                const char *requested,
                char **ret_session,
                char **ret_path,
                char ***ret_candidates) {

        _cleanup_free_ char *peer_session = NULL, *selected = NULL, *path = NULL;
        char **sessions = NULL;
        int n, r;

        *ret_session = NULL;
        *ret_path = NULL;
        *ret_candidates = NULL;

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
        if (n == 0) {
                strv_free(sessions);
                return -ENXIO;
        }
        *ret_candidates = sessions;
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
        sd_bus_slot_unref(v->validation_slot);
        sd_varlink_unref(v->link);
        free(v->user);
        free(v->reason);
        free(v->session);
        free(v->session_path);
        strv_free(v->candidate_sessions);
        free(v->candidate_path);
        free(v);
}

static void verification_error(Verification *v, const char *error) {
        if (!v->client_gone)
                (void) sd_varlink_error(v->link, error, NULL);
        verification_free(v);
}

static const char *session_error(int error) {
        if (error == -ENOTUNIQ)
                return "io.platformd.Verify.AmbiguousSession";
        if (error == -EACCES || error == -EHOSTDOWN)
                return "io.platformd.Verify.SessionNotEligible";
        return "io.platformd.Verify.NoSession";
}

static void verification_cancel(Verification *v) {
        if (!v || v->cancelled)
                return;

        v->cancelled = true;
        if (v->pid > 0)
                (void) kill(v->pid, SIGTERM);
        else
                verification_complete(v);
}

static int on_session_properties(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Verification *v = userdata;
        const char *interface, *name;
        int locked = -1, r;
        bool invalidated = false;

        if (sd_bus_message_read(message, "s", &interface) <= 0)
                goto cancel;
        if (!streq(interface, "org.freedesktop.login1.Session"))
                return 0;
        if (sd_bus_message_enter_container(message, 'a', "{sv}") <= 0)
                goto cancel;
        while ((r = sd_bus_message_enter_container(message, 'e', "sv")) > 0) {
                if (sd_bus_message_read(message, "s", &name) <= 0)
                        goto cancel;
                if (streq(name, "LockedHint")) {
                        if (locked >= 0 || sd_bus_message_enter_container(message, 'v', "b") <= 0 ||
                            sd_bus_message_read(message, "b", &locked) <= 0 ||
                            sd_bus_message_exit_container(message) < 0)
                                goto cancel;
                } else if (sd_bus_message_skip(message, "v") < 0)
                        goto cancel;
                if (sd_bus_message_exit_container(message) < 0)
                        goto cancel;
        }
        if (r < 0 || sd_bus_message_exit_container(message) < 0 ||
            sd_bus_message_enter_container(message, 'a', "s") <= 0)
                goto cancel;
        while ((r = sd_bus_message_read(message, "s", &name)) > 0)
                invalidated |= streq(name, "LockedHint");
        if (r < 0 || sd_bus_message_exit_container(message) < 0 ||
            sd_bus_message_at_end(message, true) <= 0 || locked > 0 || invalidated ||
            session_eligible(v->session, v->uid, NULL) != 1)
                goto cancel;
        return 0;
cancel:
        verification_cancel(v);
        return 0;
}

static int on_session_removed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Verification *v = userdata;
        const char *id, *path;

        if (sd_bus_message_read(message, "so", &id, &path) > 0 &&
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

static void verification_complete(Verification *v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
        bool verified;
        const char *outcome;
        int status = v->result_status;

        v->timed_out |= verification_expired(v);
        if (v->selecting) {
                verification_error(v, v->timed_out ?
                                "io.platformd.Verify.VerificationTimedOut" :
                                "io.platformd.Verify.VerificationCancelled");
                return;
        }
        if (!v->timed_out && !v->cancelled &&
            session_eligible(v->session, v->uid, NULL) != 1)
                v->cancelled = true;
        v->timed_out |= verification_expired(v);
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
}

static int on_verify_done(sd_event_source *source, const siginfo_t *si, void *userdata) {
        Verification *v = userdata;

        v->worker = sd_event_source_unref(v->worker);
        v->pid = 0;
        v->worker_finished = true;
        v->result_status = si->si_code == CLD_EXITED ? si->si_status : WORKER_AUTH_FAILED;
        v->timed_out |= verification_expired(v);
        if (v->timed_out || v->cancelled || v->client_gone || v->result_status != EXIT_SUCCESS)
                verification_complete(v);
        else if (verification_validate(v) < 0)
                verification_cancel(v);
        return 0;
}

static int on_verify_timeout(sd_event_source *source, uint64_t usec, void *userdata) {
        Verification *v = userdata;

        v->timed_out = true;
        if (v->pid > 0)
                (void) kill(v->pid, SIGTERM);
        else
                verification_complete(v);
        return 0;
}

static void on_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        for (Verification *v = g_verifications; v; v = v->next)
                if (v->link == link) {
                        v->client_gone = true;
                        v->link = sd_varlink_unref(v->link);
                        if (v->pid > 0)
                                (void) kill(v->pid, SIGTERM);
                        else
                                verification_free(v);
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
        struct passwd *pw;
        int r;

        pw = getpwuid(uid);
        if (!pw || !pw->pw_name)
                return WORKER_SETUP_FAILED;
        user = pw->pw_name;
        confdir = getenv("PLATFORMD_VERIFY_PAM_CONFDIR");
        if (confdir && *confdir)
                r = pam_start_confdir("platformd-verify", user, &conversation, confdir, &pamh);
        else
                r = pam_start("platformd-verify", user, &conversation, &pamh);
        if (r != PAM_SUCCESS)
                return WORKER_SETUP_FAILED;

        r = pam_authenticate(pamh, 0);
        (void) pam_end(pamh, r);
        if (r == PAM_SUCCESS)
                return EXIT_SUCCESS;
        if (context.prompt_status == VERIFY_PROMPT_TIMED_OUT)
                return WORKER_PROMPT_TIMED_OUT;
        if (context.prompt_status == VERIFY_PROMPT_CANCELLED)
                return WORKER_PROMPT_CANCELLED;
        if (context.prompt_status == VERIFY_PROMPT_UNAVAILABLE ||
            context.prompt_status == VERIFY_PROMPT_PROTOCOL_ERROR)
                return WORKER_PROMPT_UNAVAILABLE;
        return WORKER_AUTH_FAILED;
}

static int on_monitor_installed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        if (sd_bus_message_is_method_error(message, NULL))
                verification_cancel(userdata);
        return 0;
}

static int prepare_monitor(Verification *v) {
        int r;

#ifdef VERIFYD_TESTING
        const char *test_session = test_session_id();

        if (test_session && streq(v->session, test_session))
                return 0;
#endif

        r = sd_bus_match_signal_async(
                        g_bus,
                        &v->properties_slot,
                        "org.freedesktop.login1",
                        v->session_path,
                        "org.freedesktop.DBus.Properties",
                        "PropertiesChanged",
                        on_session_properties,
                        on_monitor_installed,
                        v);
        if (r < 0)
                return r;
        r = sd_bus_match_signal_async(
                        g_bus,
                        &v->removed_slot,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "SessionRemoved",
                        on_session_removed,
                        on_monitor_installed,
                        v);
        if (r < 0)
                return r;
        return session_eligible(v->session, v->uid, NULL) == 1 ? 0 : -EHOSTDOWN;
}

static int on_session_validated(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Verification *v = userdata;
        int locked;

        v->validation_slot = sd_bus_slot_unref(v->validation_slot);
        if (sd_bus_message_is_method_error(message, NULL) ||
            sd_bus_message_enter_container(message, 'v', "b") <= 0 ||
            sd_bus_message_read(message, "b", &locked) <= 0 || locked ||
            sd_bus_message_exit_container(message) < 0 ||
            sd_bus_message_at_end(message, true) <= 0 ||
            session_eligible(v->session, v->uid, NULL) != 1 || verification_expired(v))
                verification_cancel(v);
        else if (v->worker_finished)
                verification_complete(v);
        else if (verification_launch(v) < 0)
                verification_cancel(v);
        return 0;
}

static int verification_validate(Verification *v) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;
        int r;

#ifdef VERIFYD_TESTING
        const char *session = test_session_id();
        if (session && streq(v->session, session)) {
                if (v->worker_finished)
                        verification_complete(v);
                else
                        return verification_launch(v);
                return 0;
        }
#endif
        if (!g_bus)
                return -ENOTCONN;
        if ((r = sd_bus_message_new_method_call(g_bus, &message, "org.freedesktop.login1", v->session_path,
                                                "org.freedesktop.DBus.Properties", "Get")) < 0 ||
            (r = sd_bus_message_append(message, "ss", "org.freedesktop.login1.Session", "LockedHint")) < 0)
                return r;
        return sd_bus_call_async(g_bus, &v->validation_slot, message, on_session_validated, v, 2U * 1000000U);
}

static int verification_start(Verification *v) {
        int r;

#ifdef VERIFYD_TESTING
        if (test_session_id())
                v->user = strdup("test-user");
        else
#endif
                (void) sd_session_get_username(v->session, &v->user);
        if (!v->user)
                return -ENXIO;
        r = prepare_monitor(v);
        if (r < 0)
                return r;
        v->selecting = false;

        sd_journal_send(
                        "MESSAGE=presence verification requested",
                        "PLATFORMD_EVENT=verify-request",
                        "PLATFORMD_VERIFY_USER=%s", v->user,
                        "PLATFORMD_VERIFY_SESSION=%s", v->session,
                        "PLATFORMD_VERIFY_REASON=%s", v->reason,
                        NULL);
        return verification_validate(v);
}

static int on_candidate_validated(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Verification *v = userdata;
        const char *candidate = v->candidate_sessions[v->candidate_index];
        int locked, r;

        v->validation_slot = sd_bus_slot_unref(v->validation_slot);
        if (verification_expired(v)) {
                verification_complete(v);
                return 0;
        }
        if (sd_bus_message_is_method_error(message, NULL) ||
            sd_bus_message_enter_container(message, 'v', "b") <= 0 ||
            sd_bus_message_read(message, "b", &locked) <= 0 ||
            sd_bus_message_exit_container(message) < 0 ||
            sd_bus_message_at_end(message, true) <= 0) {
                verification_error(v, "io.platformd.Verify.NoSession");
                return 0;
        }
        r = session_eligible(candidate, v->uid, NULL);
        if (r < 0) {
                verification_error(v, session_error(r));
                return 0;
        }
        if (r > 0 && !locked) {
                if (v->session) {
                        verification_error(v, "io.platformd.Verify.AmbiguousSession");
                        return 0;
                }
                v->session = strdup(candidate);
                if (!v->session) {
                        verification_error(v, "io.platformd.Verify.VerificationUnsupported");
                        return 0;
                }
                v->session_path = v->candidate_path;
                v->candidate_path = NULL;
        }
        free(v->candidate_path);
        v->candidate_path = NULL;
        v->candidate_index++;
        r = verification_select_next(v);
        if (r < 0)
                verification_error(v, session_error(r));
        return 0;
}

static int verification_select_next(Verification *v) {
        int r;

        if (verification_expired(v)) {
                verification_complete(v);
                return 0;
        }
        for (; v->candidate_sessions[v->candidate_index]; v->candidate_index++) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;

                r = session_eligible(v->candidate_sessions[v->candidate_index], v->uid, &v->candidate_path);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;
                if (!g_bus)
                        return -ENOTCONN;
                if ((r = sd_bus_message_new_method_call(g_bus, &message, "org.freedesktop.login1",
                                                        v->candidate_path, "org.freedesktop.DBus.Properties", "Get")) < 0 ||
                    (r = sd_bus_message_append(message, "ss", "org.freedesktop.login1.Session", "LockedHint")) < 0)
                        return r;
                return sd_bus_call_async(g_bus, &v->validation_slot, message, on_candidate_validated,
                                         v, 2U * 1000000U);
        }
        strv_free(v->candidate_sessions);
        v->candidate_sessions = NULL;
        if (!v->session)
                return -ENXIO;
        return verification_start(v);
}

static int verification_launch(Verification *v) {
        pid_t pid;
        int r;

        if (verification_expired(v))
                return -ETIMEDOUT;
        pid = verify_worker_fork();
        if (pid < 0)
                return pid;
        if (pid == 0) {
                char uid[32];

                snprintf(uid, sizeof uid, "%u", (unsigned) v->uid);
                execl("/proc/self/exe", "platformd-verifyd", "--pam-worker", uid, v->user, v->reason, NULL);
                _exit(WORKER_SETUP_FAILED);
        }
        v->pid = pid;
        r = sd_event_add_child(g_event, &v->worker, pid, WEXITED, on_verify_done, v);
        if (r < 0) {
                (void) kill(pid, SIGTERM);
                while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
                        ;
                v->pid = 0;
        }
        return r;
}

static int vl_verify_user(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        _cleanup_free_ char *session = NULL, *session_object = NULL;
        char **candidates = NULL;
        const char *requested, *reason;
        Verification *v = NULL;
        sd_json_variant *p;
        uid_t peer;
        pid_t peer_pid;
        int r;

        if (sd_varlink_get_peer_uid(link, &peer) < 0 ||
            sd_varlink_get_peer_pid(link, &peer_pid) < 0)
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

        r = select_session(peer, peer_pid, requested, &session, &session_object, &candidates);
        if (r < 0)
                return sd_varlink_error(link, session_error(r), NULL);

        v = calloc(1, sizeof *v);
        if (!v) {
                strv_free(candidates);
                return -ENOMEM;
        }
        v->link = sd_varlink_ref(link);
        v->uid = peer;
        v->session = session;
        session = NULL;
        v->session_path = session_object;
        session_object = NULL;
        v->candidate_sessions = candidates;
        v->selecting = true;
        v->reason = strdup(reason);
        v->result_status = WORKER_SETUP_FAILED;
        if (!v->reason ||
            sd_event_add_time_relative(g_event, &v->timeout, CLOCK_BOOTTIME, g_verify_timeout, 0,
                                       on_verify_timeout, v) < 0 ||
            sd_event_source_get_time(v->timeout, &v->deadline_usec) < 0) {
                verification_free(v);
                return sd_varlink_error(link, "io.platformd.Verify.SessionNotEligible", NULL);
        }

        v->next = g_verifications;
        g_verifications = v;
        g_n_verifications++;
        r = candidates ? verification_select_next(v) : verification_start(v);
        if (r < 0)
                verification_error(v, session_error(r));
        return 0;
}

static int setup_varlink(sd_varlink_server *server, sd_event *event) {
        _cleanup_free_ char *address = NULL, *lock_path = NULL;
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
        if (asprintf(&lock_path, "%s/lock", directory) < 0)
                return -ENOMEM;
        g_listener_lock = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (g_listener_lock < 0 || flock(g_listener_lock, LOCK_EX | LOCK_NB) < 0)
                return -errno;

        r = sd_varlink_server_bind_method(
                        server,
                        "io.platformd.Verify.VerifyUser",
                        vl_verify_user);
        if (r < 0)
                return r;
        if ((r = sd_varlink_server_add_interface(server, &vl_interface_io_platformd_Verify)) < 0 ||
            (r = sd_varlink_server_set_info(server, "platformd", "platformd-verifyd", PROGRAM_VERSION,
                                           "https://github.com/CoastLineSec/platformd-verifyd")) < 0)
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

static int on_dependency_lost(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        for (Verification *v = g_verifications, *next; v; v = next) {
                next = v->next;
                verification_cancel(v);
        }
        return sd_event_exit(g_event, EXIT_FAILURE);
}

static int on_logind_owner_changed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *name, *old_owner, *new_owner;

        if (sd_bus_message_read(message, "sss", &name, &old_owner, &new_owner) <= 0 ||
            !streq(name, "org.freedesktop.login1") || !*old_owner || streq(old_owner, new_owner))
                return 0;
        for (Verification *v = g_verifications, *next; v; v = next) {
                next = v->next;
                verification_cancel(v);
        }
        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        const char *timeout;
        struct sigaction action = { .sa_handler = SIG_DFL };
        sigset_t signals;
        int r;

        if (argc == 2 && (streq(argv[1], "--help") || streq(argv[1], "-h"))) {
                puts("platformd-verifyd [OPTIONS...]\n\nVerify user presence with PAM.\n\n"
                     "  -h --help     Show this help\n"
                     "     --version  Show package version");
                return EXIT_SUCCESS;
        }
        if (argc == 2 && streq(argv[1], "--version")) {
                puts("platformd-verifyd " PROGRAM_VERSION);
                return EXIT_SUCCESS;
        }
        if (argc != 1 && !streq(argv[1], "--pam-worker")) {
                fprintf(stderr, "Unexpected argument: %s\n", argv[1]);
                return EXIT_FAILURE;
        }
        timeout = getenv("PLATFORMD_VERIFY_TIMEOUT_SEC");
        if (timeout && *timeout) {
                char *end = NULL;
                unsigned long seconds;

                errno = 0;
                seconds = strtoul(timeout, &end, 10);
                if (errno != 0 || timeout[0] < '0' || timeout[0] > '9' || *end || seconds == 0 || seconds > 600) {
                        fprintf(stderr, "Invalid verification timeout: %s\n", timeout);
                        return EXIT_FAILURE;
                }
                g_verify_timeout = seconds * 1000000U;
        }

        if (argc > 1 && streq(argv[1], "--pam-worker")) {
                unsigned long uid;
                char *end;

                if (argc != 5 || !argv[2][0] || !argv[3][0] ||
                    !verify_text_valid(argv[4], VERIFY_REASON_MAX))
                        return WORKER_SETUP_FAILED;
                errno = 0;
                uid = strtoul(argv[2], &end, 10);
                if (errno != 0 || *end || uid >= (uid_t) -1 ||
                    (getuid() != 0 && uid != getuid()))
                        return WORKER_SETUP_FAILED;
                return worker_run((uid_t) uid, argv[3], argv[4]);
        }

        r = sd_event_default(&event);
        if (r < 0) {
                sd_journal_print(LOG_ERR, "Failed to allocate event loop: %s", strerror(-r));
                return EXIT_FAILURE;
        }
        g_event = event;

        sigemptyset(&signals);
        sigaddset(&signals, SIGTERM);
        sigaddset(&signals, SIGINT);
        sigaddset(&signals, SIGCHLD);
        sigemptyset(&action.sa_mask);
        if (sigprocmask(SIG_BLOCK, &signals, NULL) < 0 ||
            sigaction(SIGCHLD, &action, NULL) < 0 ||
            sigaction(SIGTERM, &action, NULL) < 0 ||
            sigaction(SIGINT, &action, NULL) < 0) {
                sd_journal_print(LOG_ERR, "Failed to configure verification signals: %m");
                return EXIT_FAILURE;
        }
        if ((r = sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL)) < 0 ||
            (r = sd_event_add_signal(event, NULL, SIGINT, NULL, NULL)) < 0) {
                sd_journal_print(LOG_ERR, "Failed to install termination handlers: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        r = sd_bus_open_system(&bus);
        if (r >= 0)
                r = sd_bus_attach_event(bus, event, SD_EVENT_PRIORITY_NORMAL);
        if (r >= 0)
                r = sd_bus_match_signal(bus, NULL, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                         "org.freedesktop.DBus", "NameOwnerChanged", on_logind_owner_changed, NULL);
        if (r >= 0)
                r = sd_bus_match_signal(bus, NULL, NULL, "/org/freedesktop/DBus/Local",
                                         "org.freedesktop.DBus.Local", "Disconnected", on_dependency_lost, NULL);
        if (r < 0) {
                sd_journal_print(LOG_WARNING, "logind session validation is unavailable: %s",
                                 strerror(-r));
                bus = sd_bus_flush_close_unref(bus);
#ifdef VERIFYD_TESTING
                if (!test_session_id())
#endif
                        return EXIT_FAILURE;
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

        for (Verification *v = g_verifications; v; v = v->next)
                if (v->pid > 0)
                        (void) kill(v->pid, SIGTERM);
        while (g_verifications) {
                Verification *v = g_verifications;

                while (v->pid > 0 && waitpid(v->pid, NULL, 0) < 0 && errno == EINTR)
                        ;
                verification_free(v);
        }
        while (g_submissions)
                trust_submission_free(g_submissions);
        g_bus = NULL;
        if (g_listener_lock >= 0)
                close(g_listener_lock);
        g_listener_lock = -1;
        return r != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
