/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#define main verifyctl_main
#include "verifyctl.c"
#undef main

#include <assert.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static void read_request(int fd, const char *method) {
        char buffer[2048];
        size_t n = 0;

        do {
                assert(n < sizeof buffer);
                assert(read(fd, buffer + n, 1) == 1);
        } while (buffer[n++]);
        assert(strstr(buffer, method));
}

static void send_reply(int fd, const char *reply) {
        size_t size = strlen(reply) + 1;

        assert(send(fd, reply, size, MSG_NOSIGNAL) == (ssize_t) size);
}

static void run_case(unsigned mode) {
        static const char progress[] =
                "{\"parameters\":{\"message\":{\"style\":\"info\",\"text\":\"Touch reader\"}},\"continues\":true}";
        static const char missing[] =
                "{\"error\":\"org.varlink.service.MethodNotFound\",\"parameters\":{\"method\":\"io.platformd.Verify.VerifyUserWithMessages\"}}";
        sd_varlink *link = NULL;
        sd_json_variant *parameters = NULL, *result = NULL;
        char *error = NULL;
        int pair[2], r, status;
        pid_t child;

        fprintf(stderr, "client compatibility case %u\n", mode);
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
        child = fork();
        assert(child >= 0);
        if (child == 0) {
                char c;

                close(pair[0]);
                read_request(pair[1], mode >= 7 ? "\"method\":\"io.platformd.Verify.VerifyUserWithContext\"" :
                                                 "\"method\":\"io.platformd.Verify.VerifyUserWithMessages\"");
                if (mode == 0) {
                        send_reply(pair[1], missing);
                        read_request(pair[1], "\"method\":\"io.platformd.Verify.VerifyUser\"");
                        send_reply(pair[1], "{\"parameters\":{\"verified\":true,\"method\":\"platformd-verify\",\"realtimeUSec\":1}}");
                } else if (mode == 1 || mode == 4 || mode == 8) {
                        send_reply(pair[1], progress);
                        send_reply(pair[1], mode == 1 ? missing :
                                   "{\"parameters\":{\"result\":{\"verified\":true,\"method\":\"platformd-verify\",\"realtimeUSec\":1}}}");
                } else if (mode == 7)
                        send_reply(pair[1], missing);
                else if (mode == 2 || mode == 9)
                        send_reply(pair[1], "{\"error\":\"io.platformd.Verify.VerificationCancelled\",\"parameters\":{}}");
                else if (mode == 5)
                        send_reply(pair[1], "{\"parameters\":{\"message\":{\"style\":\"info\",\"text\":\"bad\\u001btext\"}},\"continues\":true}");
                else if (mode == 6)
                        send_reply(pair[1], "{\"parameters\":{\"message\":{\"style\":\"info\",\"text\":\"bad\"},\"result\":{\"verified\":true}}}");
                else {
                        close(pair[1]);
                        _exit(EXIT_SUCCESS);
                }
                /* No case except MethodNotFound before progress may start another request. */
                assert(read(pair[1], &c, 1) <= 0);
                close(pair[1]);
                _exit(EXIT_SUCCESS);
        }
        close(pair[1]);
        assert(sd_varlink_connect_fd(&link, pair[0]) >= 0);
        assert(sd_varlink_set_relative_timeout(link, 1000000U) >= 0);
        assert(sd_json_buildo(&parameters,
                              SD_JSON_BUILD_PAIR_STRING("sessionId", "test"),
                              SD_JSON_BUILD_PAIR_STRING("reason", "test")) >= 0);
        r = verify_with_messages(link, parameters, mode >= 7, &result, &error);
        fprintf(stderr, "client result %d, error=%s\n", r, error ?: "none");
        if (mode == 0 || mode == 4 || mode == 8)
                assert(r >= 0 && !error && sd_json_variant_boolean(sd_json_variant_by_key(result, "verified")));
        else if (mode == 1 || mode == 2 || mode == 7 || mode == 9)
                assert(r >= 0 && error && !result);
        else
                assert(r < 0 || error);
        sd_varlink_unref(link);
        sd_json_variant_unref(parameters);
        sd_json_variant_unref(result);
        free(error);
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
}

static void test_context_file(void) {
        static const char json[] =
                "{\"challengeHex\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\","
                "\"audience\":\"service.example\","
                "\"operationDigestHex\":\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\"}";
        sd_json_variant *context = NULL;
        char *path = NULL;
        FILE *f;
        int fd;

        assert(asprintf(&path, "%s/context.XXXXXX", getenv("TMPDIR")) >= 0);
        fd = mkstemp(path);
        assert(fd >= 0);
        f = fdopen(fd, "w");
        assert(f);
        assert(fputs(json, f) >= 0);
        assert(fclose(f) == 0);
        assert(context_load(path, &context) >= 0);
        assert(strcmp(sd_json_variant_string(sd_json_variant_by_key(context, "challengeHex")),
                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
        context = sd_json_variant_unref(context);

        f = fopen(path, "w");
        assert(f);
        assert(fwrite(json, 1, sizeof json, f) == sizeof json);
        assert(fclose(f) == 0);
        assert(context_load(path, &context) == -EINVAL && !context);

        f = fopen(path, "w");
        assert(f);
        assert(fprintf(f, "%s {}", json) > 0);
        assert(fclose(f) == 0);
        assert(context_load(path, &context) < 0 && !context);

        f = fopen(path, "w");
        assert(f);
        for (size_t i = 0; i <= VERIFY_CONTEXT_FILE_MAX; i++)
                assert(fputc(' ', f) != EOF);
        assert(fclose(f) == 0);
        assert(context_load(path, &context) == -E2BIG && !context);
        assert(unlink(path) == 0);
        assert(mkfifo(path, 0600) == 0);
        assert(context_load(path, &context) == -EINVAL && !context);
        assert(unlink(path) == 0);
        assert(context_load(path, &context) == -ENOENT && !context);
        free(path);
        assert(context_load(getenv("TMPDIR"), &context) == -EINVAL && !context);
}

int main(void) {
        test_context_file();
        for (unsigned i = 0; i < 10; i++)
                run_case(i);
        return EXIT_SUCCESS;
}
