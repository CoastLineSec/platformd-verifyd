/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>

#define sd_session_get_uid test_session_get_uid
#define sd_session_get_username test_session_get_username
#define sd_session_get_class test_session_get_class
#define sd_session_get_state test_session_get_state
#define sd_session_is_active test_session_is_active
#define sd_session_is_remote test_session_is_remote
#define sd_uid_get_sessions test_uid_get_sessions
#define sd_pid_get_session test_pid_get_session
#define sd_varlink_get_peer_uid test_varlink_get_peer_uid
#define sd_varlink_get_peer_pid test_varlink_get_peer_pid
#define main verifyd_main
#include "verifyd.c"
#undef main

#define SESSION_PATH "/org/freedesktop/login1/session/"

static bool first_locked, second_locked, malformed, unavailable, delayed, relock, accepted;
static unsigned first_queries, second_queries, n_sessions = 2;
static const char *peer_session, *result_error;
static const char *first_state = "active", *second_state = "active", *session_class = "user";
static char completed_session[32];
static sd_bus_message *pending;

int test_session_get_uid(const char *session, uid_t *uid) {
        if (!streq(session, "first") && !streq(session, "second"))
                return -ENXIO;
        *uid = getuid();
        return 0;
}

int test_session_get_username(const char *session, char **user) {
        *user = strdup("test-user");
        return *user ? 0 : -ENOMEM;
}

int test_session_get_class(const char *session, char **class) {
        *class = strdup(session_class);
        return *class ? 0 : -ENOMEM;
}

int test_session_get_state(const char *session, char **state) {
        const char *value = streq(session, "first") ? first_state : second_state;

        if (!value)
                return -ENODATA;
        *state = strdup(value);
        return *state ? 0 : -ENOMEM;
}

int test_session_is_active(const char *session) { return 1; }
int test_session_is_remote(const char *session) { return 0; }

int test_uid_get_sessions(uid_t uid, int active, char ***sessions) {
        *sessions = calloc(n_sessions + 1, sizeof(char *));
        assert(*sessions);
        for (unsigned i = 0; i < n_sessions; i++) {
                (*sessions)[i] = strdup(i == 0 ? "first" : "second");
                assert((*sessions)[i]);
        }
        return (int) n_sessions;
}

int test_pid_get_session(pid_t pid, char **session) {
        if (!peer_session)
                return -ENODATA;
        *session = strdup(peer_session);
        return *session ? 0 : -ENOMEM;
}

int test_varlink_get_peer_uid(sd_varlink *link, uid_t *uid) {
        *uid = getuid();
        return 0;
}

int test_varlink_get_peer_pid(sd_varlink *link, pid_t *pid) {
        *pid = getpid();
        return 0;
}

int __wrap_sd_varlink_reply(sd_varlink *link, sd_json_variant *parameters) {
        accepted = sd_json_variant_boolean(sd_json_variant_by_key(parameters, "verified"));
        assert(g_verifications && g_verifications->session);
        assert(snprintf(completed_session, sizeof completed_session, "%s", g_verifications->session) > 0);
        return 0;
}

int __wrap_sd_varlink_error(sd_varlink *link, const char *error, sd_json_variant *parameters) {
        result_error = error;
        return 0;
}

int __wrap_sd_journal_send(const char *format, ...) { return 0; }

static int get_property(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        bool first;

        if (!sd_bus_message_is_method_call(message, "org.freedesktop.DBus.Properties", "Get"))
                return 0;
        first = streq(sd_bus_message_get_path(message), SESSION_PATH "first");
        if (first)
                first_queries++;
        else
                second_queries++;
        if (delayed) {
                assert(!pending);
                pending = sd_bus_message_ref(message);
                return 1;
        }
        if (!first && malformed)
                return sd_bus_reply_method_return(message, "v", "s", "invalid");
        if (!first && unavailable)
                return sd_bus_reply_method_errorf(message, SD_BUS_ERROR_UNKNOWN_PROPERTY, "Unavailable");
        return sd_bus_reply_method_return(message, "v", "b",
                        first ? first_locked || (relock && first_queries > 1) : second_locked);
}

static void request(const char *session) {
        sd_json_variant *parameters = NULL;

        assert(sd_json_buildo(&parameters,
                        SD_JSON_BUILD_PAIR_STRING("sessionId", session),
                        SD_JSON_BUILD_PAIR_STRING("reason", "session selection test")) >= 0);
        assert(vl_verify_user(NULL, parameters, 0, NULL) >= 0);
        sd_json_variant_unref(parameters);
}

static void start_request(const char *session, uint64_t timeout) {
        assert(!g_verifications && !g_n_verifications && !pending);
        first_queries = second_queries = 0;
        accepted = false;
        result_error = NULL;
        completed_session[0] = 0;
        g_verify_timeout = timeout;
        request(session);
        if (g_verifications) {
                g_verifications->worker_finished = true;
                g_verifications->result_status = EXIT_SUCCESS;
        }
}

static void await_completion(void) {
        for (unsigned i = 0; g_verifications && i < 600; i++)
                assert(sd_event_run(g_event, 10000) >= 0);
        assert(!g_verifications && !g_n_verifications);
}

static void await_request(void) {
        for (unsigned i = 0; !pending && i < 500; i++)
                assert(sd_event_run(g_event, 10000) >= 0);
        assert(pending);
}

int main(void) {
        sd_bus *sender = NULL;

        assert(session_eligible("first", getuid(), NULL) == 1);
        session_class = "user-light";
        assert(session_eligible("first", getuid(), NULL) == 1);
        session_class = "user";
        first_state = "closing";
        assert(session_eligible("first", getuid(), NULL) == 0);
        first_state = "opening";
        assert(session_eligible("first", getuid(), NULL) == 0);
        first_state = "online";
        assert(session_eligible("first", getuid(), NULL) == 0);
        first_state = "";
        assert(session_eligible("first", getuid(), NULL) == 0);
        first_state = NULL;
        assert(session_eligible("first", getuid(), NULL) == -EIO);
        first_state = "active";

        assert(sd_event_new(&g_event) >= 0);
        assert(sd_bus_open_user(&sender) >= 0);
        assert(sd_bus_attach_event(sender, g_event, 0) >= 0);
        assert(sd_bus_add_object(sender, NULL, SESSION_PATH "first", get_property, NULL) >= 0);
        assert(sd_bus_add_object(sender, NULL, SESSION_PATH "second", get_property, NULL) >= 0);
        assert(sd_bus_request_name(sender, "org.freedesktop.login1", 0) >= 0);
        assert(sd_bus_open_user(&g_bus) >= 0);
        assert(sd_bus_attach_event(g_bus, g_event, 0) >= 0);
        assert(sd_bus_match_signal(g_bus, NULL, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                   "org.freedesktop.DBus", "NameOwnerChanged", on_logind_owner_changed, NULL) >= 0);

        first_state = "closing";
        start_request("first", 5000000);
        assert(!g_verifications && !accepted && streq(result_error, "io.platformd.Verify.SessionNotEligible"));
        assert(first_queries == 0 && second_queries == 0);
        start_request("", 5000000);
        await_completion();
        assert(accepted && !result_error && streq(completed_session, "second"));
        assert(first_queries == 0 && second_queries == 2);
        second_state = "closing";
        start_request("", 5000000);
        await_completion();
        assert(!accepted && streq(result_error, "io.platformd.Verify.NoSession"));
        assert(first_queries == 0 && second_queries == 0);
        first_state = second_state = "active";

        first_locked = true;
        start_request("", 5000000);
        await_completion();
        assert(accepted && !result_error && streq(completed_session, "second"));
        assert(first_queries == 1 && second_queries == 2);

        first_locked = false;
        second_locked = true;
        start_request("", 5000000);
        await_completion();
        assert(accepted && !result_error && streq(completed_session, "first"));
        assert(first_queries == 2 && second_queries == 1);

        second_locked = false;
        start_request("", 5000000);
        await_completion();
        assert(!accepted && streq(result_error, "io.platformd.Verify.AmbiguousSession"));

        first_locked = second_locked = true;
        start_request("", 5000000);
        await_completion();
        assert(!accepted && streq(result_error, "io.platformd.Verify.NoSession"));

        n_sessions = 0;
        start_request("", 5000000);
        assert(!g_verifications && !accepted && streq(result_error, "io.platformd.Verify.NoSession"));
        n_sessions = 2;

        first_locked = second_locked = false;
        malformed = true;
        start_request("", 5000000);
        await_completion();
        assert(!accepted && streq(result_error, "io.platformd.Verify.NoSession"));
        malformed = false;
        unavailable = true;
        start_request("", 5000000);
        await_completion();
        assert(!accepted && streq(result_error, "io.platformd.Verify.NoSession"));
        unavailable = false;

        second_locked = relock = true;
        start_request("", 5000000);
        await_completion();
        assert(!accepted && streq(result_error, "io.platformd.Verify.VerificationCancelled"));
        assert(first_queries == 2 && second_queries == 1);
        second_locked = relock = false;

        peer_session = "first";
        start_request("", 5000000);
        await_completion();
        assert(accepted && !result_error && streq(completed_session, "first"));
        assert(first_queries == 1 && second_queries == 0);
        peer_session = NULL;

        start_request("missing", 5000000);
        assert(!g_verifications && !accepted && streq(result_error, "io.platformd.Verify.SessionNotEligible"));
        first_locked = true;
        start_request("first", 5000000);
        await_completion();
        assert(!accepted && streq(result_error, "io.platformd.Verify.VerificationCancelled"));
        assert(first_queries == 1 && second_queries == 0);
        first_locked = false;

        delayed = true;
        start_request("", 100000);
        await_request();
        usleep(150000);
        assert(sd_bus_reply_method_return(pending, "v", "b", false) >= 0);
        pending = sd_bus_message_unref(pending);
        await_completion();
        assert(!accepted && streq(result_error, "io.platformd.Verify.VerificationTimedOut"));

        start_request("", 5000000);
        await_request();
        await_completion();
        assert(!accepted && streq(result_error, "io.platformd.Verify.NoSession"));
        pending = sd_bus_message_unref(pending);

        start_request("", 5000000);
        await_request();
        assert(verification_for_uid(getuid()) == g_verifications && g_n_verifications == 1);
        request("");
        assert(streq(result_error, "io.platformd.Verify.Busy"));
        result_error = NULL;
        on_disconnect(NULL, NULL, NULL);
        assert(!g_verifications && !g_n_verifications && !accepted && !result_error);
        assert(sd_bus_reply_method_return(pending, "v", "b", false) >= 0);
        pending = sd_bus_message_unref(pending);

        start_request("", 5000000);
        await_request();
        assert(sd_bus_release_name(sender, "org.freedesktop.login1") >= 0);
        await_completion();
        assert(!accepted && streq(result_error, "io.platformd.Verify.VerificationCancelled"));
        pending = sd_bus_message_unref(pending);

        assert(!g_submissions);
        sd_bus_flush_close_unref(sender);
        g_bus = sd_bus_flush_close_unref(g_bus);
        g_event = sd_event_unref(g_event);
        return EXIT_SUCCESS;
}
