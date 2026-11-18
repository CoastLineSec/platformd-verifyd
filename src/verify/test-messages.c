/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#define VERIFYD_TESTING
#define main verifyd_main
#include "verifyd.c"
#undef main

#include <assert.h>
#include <dirent.h>
#include <stdarg.h>

static unsigned notifications, replies, errors;
static bool fail_notification;

int __wrap_sd_varlink_notifyb(sd_varlink *link, ...) {
        sd_json_variant *parameters = NULL, *message, *style;
        va_list ap;

        va_start(ap, link);
        assert(sd_json_buildv(&parameters, ap) >= 0);
        va_end(ap);
        message = sd_json_variant_by_key(parameters, "message");
        assert(sd_json_variant_is_object(message));
        assert(!sd_json_variant_by_key(parameters, "result"));
        style = sd_json_variant_by_key(message, "style");
        assert(streq(sd_json_variant_string(style), notifications % 2 ? "error" : "info"));
        assert(!replies && !errors);
        notifications++;
        sd_json_variant_unref(parameters);
        return fail_notification ? -ENOBUFS : 0;
}

int __wrap_sd_varlink_reply(sd_varlink *link, sd_json_variant *parameters) {
        sd_json_variant *result = sd_json_variant_by_key(parameters, "result");

        assert(sd_json_variant_boolean(sd_json_variant_by_key(result, "verified")));
        assert(!sd_json_variant_by_key(parameters, "message"));
        replies++;
        return 0;
}

int __wrap_sd_varlink_error(sd_varlink *link, const char *error, sd_json_variant *parameters) {
        assert(streq(error, "io.platformd.Verify.VerificationCancelled"));
        errors++;
        return 0;
}

int __wrap_sd_journal_send(const char *format, ...) {
        return 0;
}

static void test_bad_record(const void *data, size_t size) {
        VerifyMessage message;
        int pair[2];

        assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
        assert(send(pair[1], data, size, MSG_NOSIGNAL) == (ssize_t) size);
        assert(verify_message_receive(pair[0], &message) == -EBADMSG);
        close(pair[0]);
        close(pair[1]);
}

static void test_transport(void) {
        VerifyMessageState state;
        VerifyMessage message;
        char long_record[sizeof message + 1];
        int pair[2], small = 1024;

        test_bad_record("", 0);
        test_bad_record("x", 1);
        test_bad_record("\x03x", 2);
        test_bad_record("\x01x", 3);
        test_bad_record("\x03\n", 3);
        test_bad_record("\x03\0x", 4);
        memset(long_record, 'x', sizeof long_record);
        test_bad_record(long_record, sizeof long_record);

        assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
        state = (VerifyMessageState) { .fd = pair[1] };
        for (unsigned i = 0; i < VERIFY_MESSAGES_MAX; i++) {
                assert(verify_message_send(&state, PAM_TEXT_INFO, "message") == 0);
                assert(verify_message_receive(pair[0], &message) == 1);
        }
        assert(verify_message_send(&state, PAM_TEXT_INFO, "overflow") == -E2BIG);
        assert(state.failed);
        state = (VerifyMessageState) { .fd = pair[1] };
        assert(verify_message_send(&state, PAM_PROMPT_ECHO_OFF, "secret") == -EINVAL);
        assert(verify_message_receive(pair[0], &message) == -EAGAIN);
        state = (VerifyMessageState) { .fd = pair[1] };
        assert(setsockopt(pair[1], SOL_SOCKET, SO_SNDBUF, &small, sizeof small) == 0);
        memset(message.text, 'x', sizeof message.text - 1);
        message.text[sizeof message.text - 1] = 0;
        for (unsigned i = 0; !state.failed && i < VERIFY_MESSAGES_MAX; i++)
                (void) verify_message_send(&state, PAM_TEXT_INFO, message.text);
        assert(state.failed && state.count < VERIFY_MESSAGES_MAX);
        close(pair[0]);
        close(pair[1]);
        assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
        close(pair[0]);
        state = (VerifyMessageState) { .fd = pair[1] };
        assert(verify_message_send(&state, PAM_ERROR_MSG, "closed") == -EPIPE);
        close(pair[1]);
        assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
        assert(send(pair[1], "", 0, MSG_NOSIGNAL) == 0);
        close(pair[1]);
        assert(verify_message_receive(pair[0], &message) == 0);
        close(pair[0]);
}

static unsigned count_fds(void) {
        DIR *directory = opendir("/proc/self/fd");
        unsigned n = 0;

        assert(directory);
        while (readdir(directory))
                n++;
        closedir(directory);
        return n;
}

static void test_rights(void) {
        VerifyMessage payload = { .style = PAM_TEXT_INFO, .text = "text" }, reply;
        struct iovec iov = { .iov_base = &payload, .iov_len = 6 };
        union { struct cmsghdr alignment; char data[CMSG_SPACE(sizeof(int))]; } control = {};
        struct msghdr message = {
                .msg_iov = &iov, .msg_iovlen = 1,
                .msg_control = control.data, .msg_controllen = sizeof control.data,
        };
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        int pair[2];
        unsigned n;

        assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &pair[1], sizeof(int));
        n = count_fds();
        assert(sendmsg(pair[1], &message, MSG_NOSIGNAL) == 6);
        assert(verify_message_receive(pair[0], &reply) == -EBADMSG);
        assert(count_fds() == n);
        close(pair[0]);
        close(pair[1]);
}

static void test_completion(unsigned count, bool fail, int status, bool malformed) {
        const siginfo_t si = { .si_code = CLD_EXITED, .si_status = status };
        Verification *v = calloc(1, sizeof *v);
        VerifyMessageState state;
        int pair[2];

        assert(v);
        notifications = replies = errors = 0;
        fail_notification = fail;
        assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
        state = (VerifyMessageState) { .fd = pair[1] };
        for (unsigned i = 0; i < count; i++) {
                state.count = 0;
                assert(verify_message_send(&state, i % 2 ? PAM_ERROR_MSG : PAM_TEXT_INFO, "factor message") == 0);
        }
        if (malformed)
                assert(send(pair[1], "bad", 3, MSG_NOSIGNAL) == 3);
        close(pair[1]);
        v->messages = true;
        v->message_fd = pair[0];
        v->deadline_usec = UINT64_MAX;
        v->user = strdup("test-user");
        v->session = strdup("test-session");
        v->uid = getuid();
        g_verifications = v;
        g_n_verifications = 1;
        assert(on_verify_done(NULL, &si, v) == 0);
        assert(!g_verifications && !g_n_verifications && !g_submissions);
        assert(notifications == (fail ? 1 : count > VERIFY_MESSAGES_MAX ? VERIFY_MESSAGES_MAX : count));
        assert(replies == (!fail && !malformed && count <= VERIFY_MESSAGES_MAX && status == EXIT_SUCCESS ? 1U : 0U));
        assert(errors == (fail || malformed || count > VERIFY_MESSAGES_MAX || status == WORKER_MESSAGE_FAILED ? 1U : 0U));
}

int main(void) {
        assert(setenv("PLATFORMD_VERIFY_TEST_SESSION", "test-session", 1) == 0);
        test_transport();
        test_rights();
        test_completion(2, false, EXIT_SUCCESS, false);
        test_completion(32, false, EXIT_SUCCESS, false);
        test_completion(33, false, EXIT_SUCCESS, false);
        test_completion(2, true, EXIT_SUCCESS, false);
        test_completion(2, false, WORKER_MESSAGE_FAILED, false);
        test_completion(2, false, EXIT_SUCCESS, true);
        return EXIT_SUCCESS;
}
