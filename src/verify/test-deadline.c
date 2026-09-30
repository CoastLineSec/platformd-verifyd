/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#define VERIFYD_TESTING
#define main verifyd_main
#include "verifyd.c"
#undef main

#include <assert.h>

static bool accepted;
static bool expired;

int __wrap_sd_varlink_reply(sd_varlink *link, sd_json_variant *parameters) {
        accepted = sd_json_variant_boolean(sd_json_variant_by_key(parameters, "verified"));
        return 0;
}

int __wrap_sd_varlink_error(sd_varlink *link, const char *error, sd_json_variant *parameters) {
        expired = streq(error, "io.platformd.Verify.VerificationTimedOut");
        return 0;
}

int __wrap_sd_journal_send(const char *format, ...) {
        return 0;
}

int main(void) {
        sigset_t signals;
        Verification *v;
        pid_t child;
        uint64_t completed;
        int report[2];

        assert(setenv("PLATFORMD_VERIFY_TEST_SESSION", "test-session", 1) == 0);
        assert(sd_event_new(&g_event) >= 0);
        sigemptyset(&signals);
        sigaddset(&signals, SIGCHLD);
        assert(sigprocmask(SIG_BLOCK, &signals, NULL) == 0);
        v = calloc(1, sizeof *v);
        assert(v);
        v->user = strdup("test-user");
        v->session = strdup("test-session");
        v->session_path = strdup("/org/freedesktop/login1/session/test");
        assert(v->user && v->session && v->session_path);
        v->uid = getuid();
        g_verifications = v;
        g_n_verifications = 1;

        assert(pipe(report) == 0);
        child = fork();
        assert(child >= 0);
        if (child == 0) {
                struct timespec now;

                close(report[0]);
                usleep(1200000);
                assert(clock_gettime(CLOCK_BOOTTIME, &now) == 0);
                completed = (uint64_t) now.tv_sec * 1000000U + now.tv_nsec / 1000U;
                assert(write(report[1], &completed, sizeof completed) == sizeof completed);
                _exit(EXIT_SUCCESS);
        }
        close(report[1]);
        v->pid = child;
        assert(sd_event_add_child(g_event, &v->worker, child, WEXITED, on_verify_done, v) >= 0);
        assert(sd_event_add_time_relative(g_event, &v->timeout, CLOCK_BOOTTIME,
                                         1000000U, 0, on_verify_timeout, v) >= 0);
        assert(sd_event_source_get_time(v->timeout, &v->deadline_usec) >= 0);
        usleep(1600000);
        assert(read(report[0], &completed, sizeof completed) == sizeof completed);
        close(report[0]);
        assert(completed > v->deadline_usec);
        while (g_verifications)
                assert(sd_event_run(g_event, UINT64_MAX) >= 0);
        assert(expired);
        assert(!accepted);
        assert(!g_submissions);
        g_event = sd_event_unref(g_event);
        return EXIT_SUCCESS;
}
