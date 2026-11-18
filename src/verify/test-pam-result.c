/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG

#define main verifyd_main
#include "verifyd.c"
#undef main

#include <assert.h>

static int method_ask(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        sd_json_variant *v;
        const char *message;

        v = sd_json_variant_by_key(parameters, "message");
        assert(v && sd_json_variant_is_string(v));
        message = sd_json_variant_string(v);

        if (strstr(message, "Unavailable"))
                return sd_varlink_error(link, "io.systemd.AskPassword.NoPasswordAvailable", NULL);
        if (strstr(message, "Timeout"))
                return sd_varlink_error(link, "io.systemd.AskPassword.TimeoutReached", NULL);
        if (strstr(message, "Malformed"))
                return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("passwords", "invalid"));

        assert(strstr(message, "Password"));
        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR(
                                        "passwords",
                                        SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_STRING("test-password"))));
}

static void run_server(const char *path, int ready_fd) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;

        assert(sd_event_new(&event) >= 0);
        assert(sd_varlink_server_new(&server, 0) >= 0);
        assert(sd_varlink_server_bind_method(server, "io.systemd.AskPassword.Ask", method_ask) >= 0);
        assert(sd_varlink_server_listen_address(server, path, 0600) >= 0);
        assert(sd_varlink_server_attach_event(server, event, 0) >= 0);
        assert(write(ready_fd, "1", 1) == 1);
        assert(close(ready_fd) == 0);
        assert(sd_event_loop(event) >= 0);
}

int main(int argc, char **argv) {
        static const struct {
                const char *arguments;
                const char *fallback;
                int expected;
        } cases[] = {
                { "permit",             NULL,     EXIT_SUCCESS              },
                { "deny",               NULL,     WORKER_AUTH_FAILED        },
                { "prompt Password",    NULL,     EXIT_SUCCESS              },
                { "prompt Unavailable", NULL,     WORKER_PROMPT_UNAVAILABLE },
                { "prompt Timeout",     NULL,     WORKER_PROMPT_TIMED_OUT   },
                { "prompt Malformed",   NULL,     WORKER_PROMPT_UNAVAILABLE },
                { "prompt Unavailable", "permit", EXIT_SUCCESS              },
                { "prompt Timeout",     "permit", EXIT_SUCCESS              },
                { "prompt Malformed",   "permit", EXIT_SUCCESS              },
                { "retry Unavailable",  NULL,     EXIT_SUCCESS              },
                { "retry Timeout",      NULL,     EXIT_SUCCESS              },
                { "retry Malformed",    NULL,     EXIT_SUCCESS              },
                { "prompt Unavailable", "deny",   WORKER_PROMPT_UNAVAILABLE },
                { "prompt Timeout",     "deny",   WORKER_PROMPT_TIMED_OUT   },
                { "prompt Malformed",   "deny",   WORKER_PROMPT_UNAVAILABLE },
        };
        _cleanup_free_ char *directory = NULL, *config = NULL, *socket_path = NULL, *module = NULL;
        const char *tmpdir;
        int ready[2], status;
        pid_t pid;
        char c;

        assert(argc == 2);
        module = realpath(argv[1], NULL);
        assert(module && !strpbrk(module, " \t\n\r"));
        tmpdir = getenv("TMPDIR");
        assert(tmpdir && tmpdir[0] == '/');
        assert(asprintf(&directory, "%s/pam-result.XXXXXX", tmpdir) >= 0);
        assert(mkdtemp(directory));
        assert(asprintf(&config, "%s/platformd-verify", directory) >= 0);
        assert(asprintf(&socket_path, "%s/ask-password", directory) >= 0);
        assert(setenv("PLATFORMD_VERIFY_PAM_CONFDIR", directory, 1) == 0);
        assert(setenv("PLATFORMD_ASK_PASSWORD_SOCKET", socket_path, 1) == 0);

        assert(pipe(ready) == 0);
        pid = fork();
        assert(pid >= 0);
        if (pid == 0) {
                assert(close(ready[0]) == 0);
                run_server(socket_path, ready[1]);
                _exit(EXIT_SUCCESS);
        }
        assert(close(ready[1]) == 0);
        assert(read(ready[0], &c, 1) == 1 && c == '1');
        assert(close(ready[0]) == 0);

        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
                FILE *f;
                int r;

                f = fopen(config, "we");
                assert(f);
                assert(fprintf(f, "auth %s %s %s\n",
                               cases[i].fallback ? "sufficient" : "required",
                               module, cases[i].arguments) > 0);
                if (cases[i].fallback)
                        assert(fprintf(f, "auth required %s %s\n", module, cases[i].fallback) > 0);
                assert(fclose(f) == 0);

                r = worker_run(getuid(), "test-user", "PAM result test", -1);
                fprintf(stderr, "%s, fallback=%s: %d (expected %d)\n",
                        cases[i].arguments, cases[i].fallback ?: "none", r, cases[i].expected);
                assert(r == cases[i].expected);
        }

        {
                int pair[2];
                FILE *f = fopen(config, "we");

                assert(f && fprintf(f, "auth required %s messages\n", module) > 0);
                assert(fclose(f) == 0);
                assert(worker_run(getuid(), "test-user", "legacy messages", -1) == EXIT_SUCCESS);
                assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
                assert(worker_run(getuid(), "test-user", "stream overflow", pair[1]) == WORKER_MESSAGE_FAILED);
                close(pair[0]);
                close(pair[1]);
        }

        assert(kill(pid, SIGTERM) == 0);
        assert(waitpid(pid, &status, 0) == pid);
        assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
        assert(unlink(socket_path) == 0);
        assert(unlink(config) == 0);
        assert(rmdir(directory) == 0);
        return EXIT_SUCCESS;
}
