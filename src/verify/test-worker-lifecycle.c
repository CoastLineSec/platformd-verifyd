/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/pidfd.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>

typedef struct Reply {
        bool done;
        bool verified;
        char error[128];
} Reply;

static volatile sig_atomic_t interrupted;
static const char *current_case;
static char *daemon_log;
static pid_t daemon_pid;
static bool streaming;

static uint64_t now_monotonic(void) {
        struct timespec ts;

        if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
                abort();
        return (uint64_t) ts.tv_sec * 1000000U + (uint64_t) ts.tv_nsec / 1000U;
}

static void cleanup(void) {
        uint64_t deadline = now_monotonic() + 5U * 1000000U;

        (void) signal(SIGTERM, SIG_IGN);
        (void) signal(SIGINT, SIG_IGN);
        if (daemon_pid > 0)
                (void) kill(daemon_pid, SIGTERM);

        while (now_monotonic() < deadline) {
                FILE *f;
                long child;
                pid_t pid;

                f = fopen("/proc/thread-self/children", "re");
                if (!f)
                        abort();
                while (fscanf(f, "%ld", &child) == 1)
                        if (child > 0)
                                (void) kill((pid_t) child, SIGKILL);
                (void) fclose(f);

                do
                        pid = waitpid(-1, NULL, WNOHANG);
                while (pid > 0 || (pid < 0 && errno == EINTR));
                if (pid < 0 && errno == ECHILD) {
                        daemon_pid = 0;
                        return;
                }
                usleep(10000);
        }
        fputs("Failed to reap test descendants\n", stderr);
        abort();
}

static void fail(const char *expression, unsigned line) {
        FILE *f;
        char buffer[512];

        fprintf(stderr, "%s: line %u: %s: %s\n", current_case ?: "setup", line, expression, strerror(errno));
        f = daemon_log ? fopen(daemon_log, "re") : NULL;
        if (f) {
                while (fgets(buffer, sizeof buffer, f))
                        fputs(buffer, stderr);
                (void) fclose(f);
        }
        exit(EXIT_FAILURE);
}

#define check(expression) do { if (!(expression)) fail(#expression, __LINE__); } while (0)

static void on_signal(int signal_number) {
        interrupted = signal_number;
}

static int on_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        Reply *reply = userdata;
        sd_json_variant *verified;

        check(!reply->done);
        if (flags & SD_VARLINK_REPLY_CONTINUES) {
                check(streaming && !error_id);
                check(sd_json_variant_is_object(sd_json_variant_by_key(parameters, "message")));
                return 0;
        }
        reply->done = true;
        if (error_id)
                check(snprintf(reply->error, sizeof reply->error, "%s", error_id) > 0);
        else {
                if (streaming)
                        parameters = sd_json_variant_by_key(parameters, "result");
                verified = sd_json_variant_by_key(parameters, "verified");
                check(verified && sd_json_variant_is_boolean(verified));
                reply->verified = sd_json_variant_boolean(verified);
        }
        return 0;
}

static sd_varlink *start_request(const char *socket_path, Reply *reply) {
        sd_varlink *link = NULL;
        sd_json_variant *parameters = NULL;

        check(sd_varlink_connect_address(&link, socket_path) >= 0);
        check(sd_varlink_set_relative_timeout(link, 5U * 1000000U) >= 0);
        sd_varlink_set_userdata(link, reply);
        check(sd_varlink_bind_reply(link, on_reply) >= 0);
        check(sd_json_buildo(&parameters,
                        SD_JSON_BUILD_PAIR_STRING("sessionId", "test-session"),
                        SD_JSON_BUILD_PAIR_STRING("reason", "worker lifecycle test")) >= 0);
        check((streaming ? sd_varlink_observe(link, "io.platformd.Verify.VerifyUserWithMessages", parameters) :
                           sd_varlink_invoke(link, "io.platformd.Verify.VerifyUser", parameters)) >= 0);
        sd_json_variant_unref(parameters);
        check(sd_varlink_flush(link) >= 0);
        return link;
}

static bool slot_busy(const char *socket_path) {
        sd_varlink *link = NULL;
        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        bool busy;

        check(sd_varlink_connect_address(&link, socket_path) >= 0);
        check(sd_varlink_set_relative_timeout(link, 2U * 1000000U) >= 0);
        check(sd_varlink_callbo(
                        link,
                        "io.platformd.Verify.VerifyUser",
                        &reply,
                        &error_id,
                        SD_JSON_BUILD_PAIR_STRING("sessionId", "no-such-session"),
                        SD_JSON_BUILD_PAIR_STRING("reason", "slot availability")) >= 0);
        check(error_id);
        busy = strcmp(error_id, "io.platformd.Verify.Busy") == 0;
        if (!busy)
                check(strcmp(error_id, "io.platformd.Verify.SessionNotEligible") == 0);
        sd_varlink_unref(link);
        return busy;
}

static void await_reply(sd_varlink *link, Reply *reply) {
        uint64_t deadline = now_monotonic() + 5U * 1000000U;

        while (!reply->done) {
                int r;

                check(!interrupted && now_monotonic() < deadline);
                r = sd_varlink_process(link);
                check(r >= 0);
                if (r == 0 && !reply->done)
                        check(sd_varlink_wait(link, 100000U) >= 0);
        }
}

static int read_pidfd(const char *directory, const char *name) {
        char *path;
        uint64_t deadline = now_monotonic() + 1000000U;
        int fd = -1;

        check(asprintf(&path, "%s/%s", directory, name) >= 0);
        while (fd < 0) {
                FILE *f;
                long pid;

                check(!interrupted && now_monotonic() < deadline);
                f = fopen(path, "re");
                if (f) {
                        if (fscanf(f, "%ld", &pid) == 1) {
                                check(pid > 0);
                                fd = pidfd_open((pid_t) pid, 0);
                                check(fd >= 0);
                        }
                        check(fclose(f) == 0);
                } else
                        check(errno == ENOENT);
                if (fd < 0)
                        usleep(1000);
        }
        free(path);
        return fd;
}

static void await_daemon_exit(void) {
        uint64_t deadline = now_monotonic() + 5U * 1000000U;
        pid_t pid;
        int status;

        do {
                check(!interrupted && now_monotonic() < deadline);
                pid = waitpid(daemon_pid, &status, WNOHANG);
                check(pid >= 0);
                if (pid == 0)
                        usleep(1000);
        } while (pid == 0);
        daemon_pid = 0;
        check(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
}

static void run_case(const char *daemon, const char *module, const char *mode) {
        char *directory, *socket_path, *config, *release;
        uint64_t deadline;
        sd_varlink *link;
        Reply reply = {};
        FILE *f;
        int pids[3];

        current_case = mode;
        check(asprintf(&directory, "%s/worker-lifecycle.XXXXXX", getenv("TMPDIR")) >= 0);
        check(mkdtemp(directory));
        check(asprintf(&socket_path, "%s/io.platformd.Verify", directory) >= 0);
        check(asprintf(&config, "%s/platformd-verify", directory) >= 0);
        check(asprintf(&release, "%s/release", directory) >= 0);
        check(asprintf(&daemon_log, "%s/daemon.log", directory) >= 0);
        f = fopen(config, "we");
        check(f);
        check(fprintf(f, "auth required %s %s\n", module, directory) > 0);
        check(fclose(f) == 0);

        daemon_pid = fork();
        check(daemon_pid >= 0);
        if (daemon_pid == 0) {
                int fd = open(daemon_log, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0600);

                if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0 ||
                    setenv("PLATFORMD_VERIFYD_RUNTIME", directory, 1) < 0 ||
                    setenv("PLATFORMD_VERIFY_PAM_CONFDIR", directory, 1) < 0 ||
                    setenv("PLATFORMD_VERIFY_TEST_SESSION", "test-session", 1) < 0 ||
                    setenv("PLATFORMD_VERIFY_TIMEOUT_SEC", "2", 1) < 0)
                        _exit(EXIT_FAILURE);
                execl(daemon, daemon, NULL);
                _exit(EXIT_FAILURE);
        }

        deadline = now_monotonic() + 5U * 1000000U;
        while (access(socket_path, F_OK) < 0) {
                check(!interrupted && now_monotonic() < deadline);
                usleep(1000);
        }

        link = start_request(socket_path, &reply);
        pids[0] = read_pidfd(directory, "worker");
        pids[1] = read_pidfd(directory, "direct");
        pids[2] = read_pidfd(directory, "detached");
        check(slot_busy(socket_path));

        if (strcmp(mode, "disconnect") == 0)
                link = sd_varlink_close_unref(link);
        else if (strcmp(mode, "sigterm") == 0)
                check(kill(daemon_pid, SIGTERM) == 0);
        else if (strcmp(mode, "success") == 0) {
                f = fopen(release, "we");
                check(f && fclose(f) == 0);
        }

        if (strcmp(mode, "sigterm") == 0) {
                await_daemon_exit();
        } else if (strcmp(mode, "disconnect") == 0) {
                deadline = now_monotonic() + 5U * 1000000U;
                while (slot_busy(socket_path)) {
                        check(!interrupted && now_monotonic() < deadline);
                        usleep(1000);
                }
        } else {
                await_reply(link, &reply);
                if (strcmp(mode, "success") == 0)
                        check(reply.verified && !reply.error[0]);
                else
                        check(strcmp(reply.error, "io.platformd.Verify.VerificationTimedOut") == 0);
                check(!slot_busy(socket_path));
        }

        for (size_t i = 0; i < sizeof pids / sizeof pids[0]; i++) {
                check(pidfd_send_signal(pids[i], 0, NULL, 0) < 0 && errno == ESRCH);
                check(close(pids[i]) == 0);
        }
        sd_varlink_unref(link);
        if (daemon_pid > 0) {
                check(kill(daemon_pid, SIGTERM) == 0);
                await_daemon_exit();
        }
        cleanup();
        check(signal(SIGTERM, on_signal) != SIG_ERR);
        check(signal(SIGINT, on_signal) != SIG_ERR);
        fprintf(stderr, "%s: no retained verification descendants\n", mode);
        free(directory);
        free(socket_path);
        free(config);
        free(release);
        free(daemon_log);
        daemon_log = NULL;
}

int main(int argc, char **argv) {
        char *daemon, *module;

        check(argc == 3);
        check(getenv("TMPDIR") && getenv("TMPDIR")[0] == '/');
        daemon = realpath(argv[1], NULL);
        module = realpath(argv[2], NULL);
        check(daemon && module && !strpbrk(module, " \t\n\r"));
        check(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0);
        check(atexit(cleanup) == 0);
        check(signal(SIGTERM, on_signal) != SIG_ERR);
        check(signal(SIGINT, on_signal) != SIG_ERR);

        run_case(daemon, module, "success");
        run_case(daemon, module, "timeout");
        run_case(daemon, module, "disconnect");
        run_case(daemon, module, "sigterm");
        streaming = true;
        run_case(daemon, module, "success");
        run_case(daemon, module, "timeout");
        run_case(daemon, module, "disconnect");
        run_case(daemon, module, "sigterm");

        free(daemon);
        free(module);
        return EXIT_SUCCESS;
}
