/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>

#define sd_session_get_uid test_session_get_uid
#define sd_session_get_class test_session_get_class
#define sd_session_is_active test_session_is_active
#define sd_session_is_remote test_session_is_remote
#define main verifyd_main
#include "verifyd.c"
#undef main

#define TEST_PATH "/org/freedesktop/login1/session/test"

static bool locked, delayed, accepted;
static const char *result_error;
static sd_bus_message *pending;

int test_session_get_uid(const char *session, uid_t *uid) {
        *uid = getuid();
        return 0;
}

int test_session_get_class(const char *session, char **class) {
        *class = strdup("user");
        return *class ? 0 : -ENOMEM;
}

int test_session_is_active(const char *session) {
        return 1;
}

int test_session_is_remote(const char *session) {
        return 0;
}

int __wrap_sd_varlink_reply(sd_varlink *link, sd_json_variant *parameters) {
        accepted = sd_json_variant_boolean(sd_json_variant_by_key(parameters, "verified"));
        return 0;
}

int __wrap_sd_varlink_error(sd_varlink *link, const char *error, sd_json_variant *parameters) {
        result_error = error;
        return 0;
}

int __wrap_sd_journal_send(const char *format, ...) {
        return 0;
}

static int get_property(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        if (!sd_bus_message_is_method_call(message, "org.freedesktop.DBus.Properties", "Get"))
                return 0;
        if (delayed) {
                assert(!pending);
                pending = sd_bus_message_ref(message);
                return 1;
        }
        return sd_bus_reply_method_return(message, "v", "b", locked);
}

static void start_validation(uint64_t timeout) {
        Verification *v = calloc(1, sizeof *v);

        assert(v);
        assert(!g_verifications && g_n_verifications == 0);
        v->user = strdup("test-user");
        v->session = strdup("test");
        v->session_path = strdup(TEST_PATH);
        assert(v->user && v->session && v->session_path);
        v->uid = getuid();
        v->worker_finished = true;
        v->result_status = EXIT_SUCCESS;
        assert(sd_event_add_time_relative(g_event, &v->timeout, CLOCK_BOOTTIME,
                                         timeout, 0, on_verify_timeout, v) >= 0);
        assert(sd_event_source_get_time(v->timeout, &v->deadline_usec) >= 0);
        assert(prepare_monitor(v) >= 0);
        g_verifications = v;
        g_n_verifications = 1;
        accepted = false;
        result_error = NULL;
        assert(verification_validate(v) >= 0);
}

static void await_completion(void) {
        for (unsigned i = 0; g_verifications && i < 500; i++)
                assert(sd_event_run(g_event, 10000) >= 0);
        assert(!g_verifications && g_n_verifications == 0);
}

static void await_request(void) {
        for (unsigned i = 0; !pending && i < 500; i++)
                assert(sd_event_run(g_event, 10000) >= 0);
        assert(pending);
}

int main(void) {
        sd_bus *sender = NULL;

        assert(sd_event_new(&g_event) >= 0);
        assert(sd_bus_open_user(&sender) >= 0);
        assert(sd_bus_attach_event(sender, g_event, 0) >= 0);
        assert(sd_bus_add_object(sender, NULL, TEST_PATH, get_property, NULL) >= 0);
        assert(sd_bus_request_name(sender, "org.freedesktop.login1", 0) >= 0);
        assert(sd_bus_open_user(&g_bus) >= 0);
        assert(sd_bus_attach_event(g_bus, g_event, 0) >= 0);
        assert(sd_bus_match_signal(g_bus, NULL, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                   "org.freedesktop.DBus", "NameOwnerChanged", on_logind_owner_changed, NULL) >= 0);

        start_validation(2000000);
        await_completion();
        assert(accepted && !result_error);

        locked = true;
        start_validation(2000000);
        await_completion();
        assert(!accepted && streq(result_error, "io.platformd.Verify.VerificationCancelled"));

        delayed = true;
        locked = false;
        start_validation(100000);
        await_request();
        usleep(150000);
        assert(sd_bus_reply_method_return(pending, "v", "b", false) >= 0);
        pending = sd_bus_message_unref(pending);
        await_completion();
        assert(!accepted && streq(result_error, "io.platformd.Verify.VerificationTimedOut"));

        start_validation(2000000);
        await_request();
        assert(sd_bus_emit_signal(sender, TEST_PATH, "org.freedesktop.DBus.Properties",
                                  "PropertiesChanged", NULL) >= 0);
        await_completion();
        assert(!accepted && streq(result_error, "io.platformd.Verify.VerificationCancelled"));
        pending = sd_bus_message_unref(pending);

        start_validation(2000000);
        await_request();
        assert(sd_bus_emit_signal(sender, "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
                                  "SessionRemoved", "so", "test", TEST_PATH) >= 0);
        await_completion();
        assert(!accepted && streq(result_error, "io.platformd.Verify.VerificationCancelled"));
        pending = sd_bus_message_unref(pending);

        start_validation(2000000);
        await_request();
        assert(sd_bus_release_name(sender, "org.freedesktop.login1") >= 0);
        await_completion();
        assert(!accepted && streq(result_error, "io.platformd.Verify.VerificationCancelled"));
        pending = sd_bus_message_unref(pending);

        start_validation(2000000);
        on_disconnect(NULL, NULL, NULL);
        assert(!g_verifications && g_n_verifications == 0);
        assert(!accepted && !result_error);

        assert(!g_submissions);
        sd_bus_flush_close_unref(sender);
        g_bus = sd_bus_flush_close_unref(g_bus);
        g_event = sd_event_unref(g_event);
        return 0;
}
