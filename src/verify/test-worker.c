/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG

#include "verify-worker.h"

#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum {
        MESSAGE_SUPERVISOR,
        MESSAGE_WORKER,
        MESSAGE_DIRECT,
        MESSAGE_NESTED,
        MESSAGE_DETACHED,
        MESSAGE_RESULT,
        MESSAGE_FAILURE,
        _MESSAGE_MAX,
};

typedef struct Message {
        int type;
        pid_t pid;
        int value;
} Message;

typedef enum TestMode {
        TEST_SUCCESS,
        TEST_FAILURE,
        TEST_CANCEL,
        TEST_DAEMON_TERM,
        TEST_DAEMON_KILL,
        TEST_SIGCHLD_IGNORE,
        TEST_SIGCHLD_NOREAP,
} TestMode;

static volatile sig_atomic_t interrupted;
static bool force_close_range_fallback;

int __real_close_range(unsigned first, unsigned last, int flags);

int __wrap_close_range(unsigned first, unsigned last, int flags) {
        if (force_close_range_fallback) {
                errno = ENOSYS;
                return -1;
        }
        return __real_close_range(first, last, flags);
}

static void on_signal(int signal) {
        interrupted = signal;
}

static uint64_t now_usec(void) {
        struct timespec ts;

        if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
                return 0;
        return (uint64_t) ts.tv_sec * 1000000U + (uint64_t) ts.tv_nsec / 1000U;
}

static void send_message(int type, int value) {
        Message message = { .type = type, .pid = getpid(), .value = value };
        ssize_t n;

        do
                n = write(STDOUT_FILENO, &message, sizeof message);
        while (n < 0 && errno == EINTR);
        if (n != sizeof message)
                _exit(EXIT_FAILURE);
}

static void child_fail(void) {
        send_message(MESSAGE_FAILURE, errno);
        _exit(EXIT_FAILURE);
}

static int read_message(int fd, Message *ret) {
        uint64_t deadline = now_usec() + 5U * 1000000U;
        size_t received = 0;

        while (received < sizeof *ret) {
                struct pollfd pfd = { .fd = fd, .events = POLLIN };
                ssize_t n;
                int r;

                if (interrupted)
                        return -EINTR;
                if (now_usec() >= deadline)
                        return -ETIMEDOUT;
                r = poll(&pfd, 1, 100);
                if (r < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                if (r == 0)
                        continue;
                n = read(fd, (char *) ret + received, sizeof *ret - received);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                if (n == 0)
                        return -EPIPE;
                received += (size_t) n;
        }

        return 0;
}

static void run_worker(int inherited_fd, int status) {
        pid_t pid;
        char command;
        int wait_status;

        errno = 0;
        if (fcntl(inherited_fd, F_GETFD) >= 0 || errno != EBADF)
                child_fail();
        send_message(MESSAGE_WORKER, getppid());

        pid = fork();
        if (pid < 0)
                child_fail();
        if (pid == 0) {
                if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0)
                        child_fail();
                send_message(MESSAGE_DIRECT, getppid());
                pid = fork();
                if (pid < 0)
                        child_fail();
                if (pid == 0)
                        send_message(MESSAGE_NESTED, getppid());
                for (;;)
                        pause();
        }

        pid = fork();
        if (pid < 0)
                child_fail();
        if (pid == 0) {
                if (setsid() < 0)
                        child_fail();
                pid = fork();
                if (pid < 0)
                        child_fail();
                if (pid > 0)
                        _exit(EXIT_SUCCESS);
                send_message(MESSAGE_DETACHED, getsid(0));
                for (;;)
                        pause();
        }

        while (waitpid(pid, &wait_status, 0) < 0)
                if (errno != EINTR)
                        child_fail();
        if (!WIFEXITED(wait_status) || WEXITSTATUS(wait_status) != EXIT_SUCCESS)
                child_fail();
        while (read(STDIN_FILENO, &command, 1) < 0)
                if (errno != EINTR)
                        child_fail();
        _exit(status);
}

static void run_daemon(int control, int messages, int guard, int status, TestMode mode) {
        pid_t pid;
        int inherited_fd, wait_status;
        struct sigaction action = { .sa_handler = SIG_DFL };

        if (sigaction(SIGTERM, &action, NULL) < 0 ||
            sigaction(SIGINT, &action, NULL) < 0 ||
            dup2(control, STDIN_FILENO) < 0 ||
            dup2(messages, STDOUT_FILENO) < 0)
                _exit(EXIT_FAILURE);
        close(control);
        close(messages);
        inherited_fd = fcntl(guard, F_DUPFD_CLOEXEC, 64);
        if (inherited_fd < 0)
                child_fail();
        if (mode == TEST_SIGCHLD_IGNORE)
                action.sa_handler = SIG_IGN;
        else if (mode == TEST_SIGCHLD_NOREAP)
                action.sa_flags = SA_NOCLDWAIT;
        if (sigaction(SIGCHLD, &action, NULL) < 0)
                child_fail();

        pid = verify_worker_fork(-1);
        if (pid < 0)
                child_fail();
        if (pid == 0)
                run_worker(inherited_fd, status);

        action.sa_handler = SIG_DFL;
        action.sa_flags = 0;
        if (sigaction(SIGCHLD, &action, NULL) < 0)
                child_fail();
        close(guard);
        close(inherited_fd);
        send_message(MESSAGE_SUPERVISOR, pid);
        while (waitpid(pid, &wait_status, 0) < 0)
                if (errno != EINTR)
                        child_fail();
        send_message(MESSAGE_RESULT, wait_status);
        _exit(EXIT_SUCCESS);
}

static int wait_child(pid_t pid, int *ret_status) {
        uint64_t deadline = now_usec() + 5U * 1000000U;

        for (;;) {
                pid_t r;

                if (interrupted)
                        return -EINTR;
                r = waitpid(pid, ret_status, WNOHANG);
                if (r == pid)
                        return 0;
                if (r < 0 && errno != EINTR)
                        return -errno;
                if (now_usec() >= deadline)
                        return -ETIMEDOUT;
                usleep(10000);
        }
}

static int children_empty(void) {
        int status;
        pid_t pid;

        errno = 0;
        pid = waitpid(-1, &status, WNOHANG);
        return pid < 0 && errno == ECHILD ? 0 : -EBUSY;
}

static int cleanup_children(void) {
        char path[128];

        snprintf(path, sizeof path, "/proc/self/task/%ld/children", (long) getpid());
        for (unsigned i = 0; i < 500; i++) {
                FILE *f;
                pid_t pid;
                int status;

                f = fopen(path, "re");
                if (!f)
                        return -errno;
                while (fscanf(f, "%d", &pid) == 1)
                        if (pid > 0)
                                (void) kill(pid, SIGKILL);
                fclose(f);

                do
                        pid = waitpid(-1, &status, WNOHANG);
                while (pid > 0 || (pid < 0 && errno == EINTR));
                if (pid < 0 && errno == ECHILD)
                        return 0;
                usleep(10000);
        }

        return -ETIMEDOUT;
}

static int test_worker(TestMode mode) {
        Message messages[_MESSAGE_MAX] = {};
        bool seen[_MESSAGE_MAX] = {};
        int control[2] = { -1, -1 }, replies[2] = { -1, -1 }, guard[2] = { -1, -1 };
        int result = -EINVAL, status, expected = mode == TEST_FAILURE ? 37 : EXIT_SUCCESS;
        pid_t daemon, supervisor, worker;
        unsigned ready = 0;

        if (pipe2(control, O_CLOEXEC) < 0 ||
            pipe2(replies, O_CLOEXEC) < 0 ||
            pipe2(guard, O_CLOEXEC) < 0)
                goto finish;
        daemon = fork();
        if (daemon < 0)
                goto finish;
        if (daemon == 0) {
                close(control[1]);
                close(replies[0]);
                close(guard[0]);
                run_daemon(control[0], replies[1], guard[1], expected, mode);
        }
        close(control[0]);
        control[0] = -1;
        close(replies[1]);
        replies[1] = -1;
        close(guard[1]);
        guard[1] = -1;

        while (ready < 5) {
                Message message;

                result = read_message(replies[0], &message);
                if (result < 0)
                        goto finish;
                if (message.type < MESSAGE_SUPERVISOR || message.type > MESSAGE_DETACHED ||
                    message.pid <= 0 || seen[message.type]) {
                        result = -EPROTO;
                        goto finish;
                }
                messages[message.type] = message;
                seen[message.type] = true;
                ready++;
        }

        result = -EPROTO;
        supervisor = messages[MESSAGE_SUPERVISOR].value;
        worker = messages[MESSAGE_WORKER].pid;
        if (supervisor <= 0 || messages[MESSAGE_SUPERVISOR].pid != daemon ||
            messages[MESSAGE_WORKER].value != supervisor ||
            messages[MESSAGE_DIRECT].value != worker ||
            messages[MESSAGE_NESTED].value != messages[MESSAGE_DIRECT].pid ||
            messages[MESSAGE_DETACHED].value <= 0 ||
            messages[MESSAGE_DETACHED].value == getsid(worker))
                goto finish;

        {
                struct pollfd pfd = { .fd = guard[0], .events = POLLIN };
                char byte;

                if (poll(&pfd, 1, 1000) <= 0 || read(guard[0], &byte, 1) != 0)
                        goto finish;
        }

        switch (mode) {
        case TEST_SUCCESS:
        case TEST_FAILURE:
        case TEST_SIGCHLD_IGNORE:
        case TEST_SIGCHLD_NOREAP:
                if (write(control[1], "x", 1) != 1)
                        goto finish;
                break;
        case TEST_CANCEL:
                if (kill(supervisor, SIGTERM) < 0)
                        goto finish;
                break;
        case TEST_DAEMON_TERM:
        case TEST_DAEMON_KILL:
                if (kill(daemon, mode == TEST_DAEMON_TERM ? SIGTERM : SIGKILL) < 0)
                        goto finish;
                break;
        }

        if (mode == TEST_DAEMON_TERM || mode == TEST_DAEMON_KILL) {
                result = wait_child(daemon, &status);
                if (result < 0)
                        goto finish;
                if (!WIFSIGNALED(status) ||
                    WTERMSIG(status) != (mode == TEST_DAEMON_TERM ? SIGTERM : SIGKILL)) {
                        result = -EPROTO;
                        goto finish;
                }
                result = wait_child(supervisor, &status);
                if (result < 0)
                        goto finish;
                if (!WIFEXITED(status) || WEXITSTATUS(status) == EXIT_SUCCESS) {
                        result = -EPROTO;
                        goto finish;
                }
        } else {
                Message message;

                result = read_message(replies[0], &message);
                if (result < 0)
                        goto finish;
                status = message.value;
                if (message.type != MESSAGE_RESULT || message.pid != daemon ||
                    !WIFEXITED(status) ||
                    (mode == TEST_CANCEL ? WEXITSTATUS(status) == EXIT_SUCCESS :
                                          WEXITSTATUS(status) != expected)) {
                        result = -EPROTO;
                        goto finish;
                }
                result = wait_child(daemon, &status);
                if (result < 0)
                        goto finish;
                if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
                        result = -EPROTO;
                        goto finish;
                }
        }

        result = children_empty();

finish:
        for (unsigned i = 0; i < 2; i++) {
                if (control[i] >= 0)
                        close(control[i]);
                if (replies[i] >= 0)
                        close(replies[i]);
                if (guard[i] >= 0)
                        close(guard[i]);
        }
        if (cleanup_children() < 0)
                result = -ECHILD;
        if (result < 0)
                fprintf(stderr, "Worker test %d failed: %d\n", mode, result);
        return result;
}

int main(void) {
        struct sigaction action = { .sa_handler = on_signal };

        if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0 ||
            sigaction(SIGTERM, &action, NULL) < 0 ||
            sigaction(SIGINT, &action, NULL) < 0)
                return EXIT_FAILURE;

        for (unsigned fallback = 0; fallback < 2; fallback++) {
                int preserve[2], guard, status;
                pid_t worker;
                char c;

                force_close_range_fallback = fallback;
                assert(pipe2(preserve, O_CLOEXEC) == 0);
                guard = fcntl(preserve[1], F_DUPFD_CLOEXEC, 64);
                assert(guard >= 64);
                worker = verify_worker_fork(preserve[1]);
                assert(worker >= 0);
                if (worker == 0) {
                        assert(fcntl(guard, F_GETFD) < 0 && errno == EBADF);
                        assert(fcntl(preserve[0], F_GETFD) < 0 && errno == EBADF);
                        assert(write(preserve[1], "x", 1) == 1);
                        _exit(EXIT_SUCCESS);
                }
                close(preserve[1]);
                close(guard);
                assert(read(preserve[0], &c, 1) == 1 && c == 'x');
                assert(read(preserve[0], &c, 1) == 0);
                close(preserve[0]);
                assert(waitpid(worker, &status, 0) == worker);
                assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
                for (unsigned i = 0; i < 10; i++)
                        for (TestMode mode = TEST_SUCCESS; mode <= TEST_SIGCHLD_NOREAP; mode++)
                                if (test_worker(mode) < 0)
                                        return EXIT_FAILURE;
        }

        puts("OK: verification worker descendants are terminated and reaped");
        return EXIT_SUCCESS;
}
