/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#define VERIFYD_TESTING
#define sd_varlink_get_peer_uid test_get_peer_uid
#define sd_varlink_get_peer_pid test_get_peer_pid
#define sd_varlink_error_invalid_parameter_name test_invalid_parameter
#define main verifyd_main
#include "verifyd.c"
#undef main

#include <assert.h>

static const char challenge[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static const char operation[] = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
static unsigned replies, errors, calls, legacy_calls;
static bool replied_verified, fail_reply, fail_authority, hold_authority;
static const char *invalid_parameter;
static sd_json_variant *submitted;
static sd_varlink *held_link;
static uint64_t reply_realtime;

int __real_sd_varlink_reply(sd_varlink *link, sd_json_variant *parameters);
int __real_sd_varlink_error(sd_varlink *link, const char *error, sd_json_variant *parameters);

int test_get_peer_uid(sd_varlink *link, uid_t *uid) {
        *uid = getuid();
        return 0;
}

int test_get_peer_pid(sd_varlink *link, pid_t *pid) {
        *pid = getpid();
        return 0;
}

int test_invalid_parameter(sd_varlink *link, const char *name) {
        invalid_parameter = name;
        return 0;
}

int __wrap_sd_varlink_reply(sd_varlink *link, sd_json_variant *parameters) {
        sd_json_variant *result = sd_json_variant_by_key(parameters, "result");

        assert(!link && sd_json_variant_is_object(result));
        assert(sd_json_variant_elements(result) == 6);
        replied_verified = sd_json_variant_boolean(sd_json_variant_by_key(result, "verified"));
        reply_realtime = sd_json_variant_unsigned(sd_json_variant_by_key(result, "realtimeUSec"));
        assert(streq(sd_json_variant_string(sd_json_variant_by_key(result, "method")), "platformd-verify"));
        replies++;
        return fail_reply ? -EPIPE : 0;
}

int __wrap_sd_varlink_error(sd_varlink *link, const char *error, sd_json_variant *parameters) {
        assert(!link);
        errors++;
        return 0;
}

int __wrap_sd_journal_send(const char *format, ...) {
        return 0;
}

static int accept_submission(sd_varlink *link, sd_json_variant *parameters,
                             sd_varlink_method_flags_t flags, void *userdata) {
        sd_json_variant *empty = NULL;
        int r;

        assert(replies == 1 && replied_verified);
        if (userdata)
                legacy_calls++;
        else
                calls++;
        assert(!submitted);
        submitted = sd_json_variant_ref(parameters);
        if (hold_authority) {
                assert(!held_link);
                held_link = sd_varlink_ref(link);
                return 0;
        }
        if (fail_authority)
                return __real_sd_varlink_error(link, "org.varlink.service.MethodNotFound", NULL);
        assert(sd_json_variant_new_object(&empty, NULL, 0) >= 0);
        r = __real_sd_varlink_reply(link, empty);
        sd_json_variant_unref(empty);
        return r;
}

static int accept_legacy_submission(sd_varlink *link, sd_json_variant *parameters,
                                    sd_varlink_method_flags_t flags, void *userdata) {
        return accept_submission(link, parameters, flags, (void *) 1);
}

static sd_json_variant *context_new(const char *audience) {
        sd_json_variant *value = NULL;

        assert(sd_json_buildo(&value,
                             SD_JSON_BUILD_PAIR_STRING("challengeHex", challenge),
                             SD_JSON_BUILD_PAIR_STRING("audience", audience),
                             SD_JSON_BUILD_PAIR_STRING("operationDigestHex", operation)) >= 0);
        return value;
}

static void context_reject(sd_json_variant *value) {
        sd_json_variant *copy = NULL, *parameters = NULL;

        assert(verify_context_parse(value, &copy) == -EINVAL && !copy);
        assert(sd_json_buildo(&parameters,
                             SD_JSON_BUILD_PAIR_STRING("sessionId", "test-session"),
                             SD_JSON_BUILD_PAIR_STRING("reason", "context test"),
                             SD_JSON_BUILD_PAIR_VARIANT("context", value)) >= 0);
        invalid_parameter = NULL;
        assert(vl_verify_user_with_context(NULL, parameters, SD_VARLINK_METHOD_MORE, NULL) >= 0);
        assert(invalid_parameter && streq(invalid_parameter, "context"));
        assert(!g_verifications && !g_n_verifications && !g_submissions);
        sd_json_variant_unref(parameters);
}

static void test_parser(void) {
        static const char * const bad_hex[] = { "", "a", "0x1234",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "gaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        };
        static const char * const bad_audience[] = { "", "newline\n", "tab\t", "delete\177", "non-ascii\303\251" };
        sd_json_variant *value = NULL, *copy = NULL;
        char audience[VERIFY_CONTEXT_AUDIENCE_MAX + 2], *duplicate = NULL;

        value = context_new("service.example");
        assert(verify_context_parse(value, &copy) >= 0);
        assert(sd_json_variant_set_field_string(&value, "audience", "changed.example") >= 0);
        assert(streq(sd_json_variant_string(sd_json_variant_by_key(copy, "audience")), "service.example"));
        assert(streq(sd_json_variant_string(sd_json_variant_by_key(copy, "challengeHex")),
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert(streq(sd_json_variant_string(sd_json_variant_by_key(copy, "operationDigestHex")),
                     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
        value = sd_json_variant_unref(value);
        copy = sd_json_variant_unref(copy);

        memset(audience, 'x', sizeof audience - 1);
        audience[sizeof audience - 1] = 0;
        value = context_new(audience);
        context_reject(value);
        value = sd_json_variant_unref(value);
        audience[VERIFY_CONTEXT_AUDIENCE_MAX] = 0;
        value = context_new(audience);
        assert(verify_context_parse(value, &copy) >= 0);
        value = sd_json_variant_unref(value);
        copy = sd_json_variant_unref(copy);

        for (size_t i = 0; i < sizeof bad_audience / sizeof bad_audience[0]; i++) {
                value = context_new(bad_audience[i]);
                context_reject(value);
                value = sd_json_variant_unref(value);
        }
        for (size_t i = 0; i < sizeof bad_hex / sizeof bad_hex[0]; i++)
                for (unsigned j = 0; j < 2; j++) {
                        value = context_new("service.example");
                        assert(sd_json_variant_set_field_string(&value, j ? "operationDigestHex" : "challengeHex", bad_hex[i]) >= 0);
                        context_reject(value);
                        value = sd_json_variant_unref(value);
                }
        for (unsigned i = 0; i < 3; i++) {
                static const char * const fields[] = { "challengeHex", "audience", "operationDigestHex" };

                value = context_new("service.example");
                assert(sd_json_variant_set_field_boolean(&value, fields[i], true) >= 0);
                context_reject(value);
                value = sd_json_variant_unref(value);
        }
        value = context_new("service.example");
        assert(sd_json_variant_set_field_string(&value, "unexpected", "value") >= 0);
        context_reject(value);
        value = sd_json_variant_unref(value);
        assert(asprintf(&duplicate, "{\"challengeHex\":\"%s\",\"audience\":\"a\",\"audience\":\"b\"}", challenge) >= 0);
        assert(sd_json_parse(duplicate, 0, &value, NULL, NULL) >= 0);
        context_reject(value);
        value = sd_json_variant_unref(value);
        free(duplicate);
        assert(sd_json_parse("{}", 0, &value, NULL, NULL) >= 0);
        context_reject(value);
        value = sd_json_variant_unref(value);
        assert(sd_json_parse("null", 0, &value, NULL, NULL) >= 0);
        context_reject(value);
        sd_json_variant_unref(value);
        assert(verify_context_parse(NULL, &copy) == -EINVAL && !copy);
        errors = 0;
        assert(vl_verify_user_with_context(NULL, NULL, 0, NULL) >= 0 && errors == 1);
}

static uint64_t clock_usec(clockid_t clock) {
        struct timespec ts;

        assert(clock_gettime(clock, &ts) == 0);
        return (uint64_t) ts.tv_sec * 1000000U + ts.tv_nsec / 1000U;
}

static void test_completion(unsigned mode) {
        sd_json_variant *value = context_new("service.example"), *context;
        uint64_t before_boot, before_real, deadline;
        Verification *v = calloc(1, sizeof *v);
        bool submit = mode == 0 || mode == 6 || mode == 7 || mode == 9;

        fprintf(stderr, "context completion case %u\n", mode);
        assert(v);
        replies = errors = calls = legacy_calls = 0;
        fail_reply = mode == 5;
        fail_authority = mode == 6;
        hold_authority = mode == 9;
        replied_verified = false;
        v->user = strdup("test-user");
        v->session = strdup(mode == 10 ? "no-such-session" : "test-session");
        v->uid = getuid();
        v->messages = true;
        v->message_fd = -1;
        v->worker_finished = true;
        v->deadline_usec = mode == 3 ? 1 : UINT64_MAX;
        v->result_status = mode == 1 ? WORKER_AUTH_FAILED : EXIT_SUCCESS;
        v->cancelled = mode == 2;
        v->client_gone = mode == 4;
        if (mode != 7)
                assert(verify_context_parse(value, &v->context) >= 0);
        sd_json_variant_unref(value);
        g_verifications = v;
        g_n_verifications = 1;
        before_boot = clock_usec(CLOCK_BOOTTIME);
        before_real = clock_usec(CLOCK_REALTIME);
        verification_complete(v);
        assert(!g_verifications && g_n_verifications == 0);
        assert(replies == (mode == 2 || mode == 3 || mode == 4 || mode == 10 ? 0U : 1U));
        assert(errors == (mode == 2 || mode == 3 || mode == 10 ? 1U : 0U));
        assert((g_submissions != NULL) == submit);
        deadline = clock_usec(CLOCK_BOOTTIME) + 3000000U;
        while (g_submissions) {
                assert(clock_usec(CLOCK_BOOTTIME) < deadline);
                assert(sd_event_run(g_event, 100000U) >= 0);
        }
        if (hold_authority)
                assert(clock_usec(CLOCK_BOOTTIME) - before_boot >= TRUST_SUBMIT_TIMEOUT_USEC);
        held_link = sd_varlink_close_unref(held_link);
        assert(calls == (submit && mode != 7 ? 1U : 0U));
        assert(legacy_calls == (mode == 7 ? 1U : 0U));
        if (!submit)
                assert(!submitted);
        else if (mode == 7)
                assert(!sd_json_variant_by_key(submitted, "context"));
        else {
                assert(sd_json_variant_elements(submitted) == 12);
                assert(streq(sd_json_variant_string(sd_json_variant_by_key(submitted, "user")), "test-user"));
                assert(sd_json_variant_unsigned(sd_json_variant_by_key(submitted, "uid")) == getuid());
                assert(streq(sd_json_variant_string(sd_json_variant_by_key(submitted, "sessionId")), "test-session"));
                context = sd_json_variant_by_key(submitted, "context");
                assert(sd_json_variant_elements(context) == 6);
                assert(streq(sd_json_variant_string(sd_json_variant_by_key(context, "audience")), "service.example"));
                assert(streq(sd_json_variant_string(sd_json_variant_by_key(context, "challengeHex")),
                             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
                assert(streq(sd_json_variant_string(sd_json_variant_by_key(context, "operationDigestHex")),
                             "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
                assert(sd_json_variant_unsigned(sd_json_variant_by_key(submitted, "verificationBoottimeUSec")) >= before_boot);
                assert(sd_json_variant_unsigned(sd_json_variant_by_key(submitted, "verificationBoottimeUSec")) <= clock_usec(CLOCK_BOOTTIME));
                assert(sd_json_variant_unsigned(sd_json_variant_by_key(submitted, "verificationRealtimeUSec")) >= before_real);
                assert(sd_json_variant_unsigned(sd_json_variant_by_key(submitted, "verificationRealtimeUSec")) <= clock_usec(CLOCK_REALTIME));
                assert(sd_json_variant_unsigned(sd_json_variant_by_key(submitted, "verificationRealtimeUSec")) == reply_realtime);
        }
        submitted = sd_json_variant_unref(submitted);
}

static void test_submission_limit(void) {
        sd_json_variant *value = context_new("service.example");
        Verification v = { .user = "test-user", .uid = getuid(), .session = "test-session" };
        unsigned n = 0;

        assert(verify_context_parse(value, &v.context) >= 0);
        sd_json_variant_unref(value);
        submit_to_trustd(&v, 0, 1);
        submit_to_trustd(&v, 1, 0);
        assert(!g_submissions);
        for (unsigned i = 0; i < TRUST_SUBMIT_MAX + 1; i++)
                submit_to_trustd(&v, 1, 1);
        for (TrustSubmission *submission = g_submissions; submission; submission = submission->next)
                n++;
        assert(n == TRUST_SUBMIT_MAX);
        while (g_submissions)
                trust_submission_free(g_submissions);
        sd_json_variant_unref(v.context);
}

int main(void) {
        sd_varlink_server *server = NULL;
        char *address = NULL;

        assert(setenv("PLATFORMD_VERIFY_TEST_SESSION", "test-session", 1) == 0);
        test_parser();
        assert(sd_event_new(&g_event) >= 0);
        assert(asprintf(&address, "%s/context-trust", getenv("XDG_RUNTIME_DIR")) >= 0);
        assert(setenv("PLATFORMD_TRUST_SOCKET", address, 1) == 0);
        assert(sd_varlink_server_new(&server, 0) >= 0);
        assert(sd_varlink_server_bind_method(server, "io.platformd.Trust.SubmitVerificationEvent", accept_submission) >= 0);
        assert(sd_varlink_server_bind_method(server, "io.platformd.Trust.SubmitAuthEvent", accept_legacy_submission) >= 0);
        assert(sd_varlink_server_listen_address(server, address, 0600) >= 0);
        assert(sd_varlink_server_attach_event(server, g_event, 0) >= 0);
        for (unsigned i = 0; i < 8; i++)
                test_completion(i);
        test_completion(9);
        test_completion(10);
        test_submission_limit();
        assert(sd_varlink_server_shutdown(server) >= 0);
        sd_varlink_server_unref(server);
        test_completion(8);
        sd_event_unref(g_event);
        assert(unlink(address) == 0);
        free(address);
        return EXIT_SUCCESS;
}
