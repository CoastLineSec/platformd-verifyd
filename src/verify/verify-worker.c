/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "verify-worker.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

static int close_inherited_fds(void) {
        struct dirent *entry;
        DIR *directory;
        int r = 0;

        if (close_range(3, UINT_MAX, 0) >= 0)
                return 0;

        directory = opendir("/proc/self/fd");
        if (!directory)
                return -errno;
        for (;;) {
                char *end;
                long fd;

                errno = 0;
                entry = readdir(directory);
                if (!entry) {
                        r = -errno;
                        break;
                }
                fd = strtol(entry->d_name, &end, 10);
                if (end == entry->d_name || *end || fd < 3 || fd > INT_MAX || fd == dirfd(directory))
                        continue;
                if (close((int) fd) < 0 && errno != EBADF && errno != EINTR) {
                        r = -errno;
                        break;
                }
        }
        (void) closedir(directory);
        return r;
}

static int kill_children(FILE *children) {
        long pid;
        int r, result = 0;

        clearerr(children);
        if (fseeko(children, 0, SEEK_SET) < 0)
                return -errno;

        /* Do not reap between enumeration and signalling: unreaped children retain their PIDs. */
        while ((r = fscanf(children, "%ld", &pid)) == 1) {
                if (pid <= 0 || pid > INT_MAX)
                        return -EBADMSG;
                if (kill((pid_t) pid, SIGKILL) < 0 && errno != ESRCH && result == 0)
                        result = -errno;
        }
        if (ferror(children))
                return -EIO;
        return r == EOF ? result : -EBADMSG;
}

pid_t verify_worker_fork(void) {
        pid_t parent = getpid(), pid;
        struct sigaction action = { .sa_handler = SIG_DFL };
        sigset_t signals;
        FILE *children;
        bool draining = false, cancelled = false, cleanup_error = false;
        int result = EXIT_FAILURE;

        pid = fork();
        if (pid != 0)
                return pid < 0 ? -errno : pid;

        sigemptyset(&signals);
        sigaddset(&signals, SIGCHLD);
        sigaddset(&signals, SIGTERM);
        sigaddset(&signals, SIGINT);
        sigemptyset(&action.sa_mask);
        if (sigprocmask(SIG_BLOCK, &signals, NULL) < 0 ||
            sigaction(SIGCHLD, &action, NULL) < 0 ||
            sigaction(SIGTERM, &action, NULL) < 0 ||
            sigaction(SIGINT, &action, NULL) < 0 ||
            prctl(PR_SET_CHILD_SUBREAPER, 1) < 0 ||
            prctl(PR_SET_PDEATHSIG, SIGTERM) < 0 ||
            getppid() != parent ||
            close_inherited_fds() < 0)
                _exit(EXIT_FAILURE);

        children = fopen("/proc/thread-self/children", "re");
        if (!children)
                _exit(EXIT_FAILURE);
        parent = getpid();
        pid = fork();
        if (pid < 0) {
                (void) fclose(children);
                _exit(EXIT_FAILURE);
        }
        if (pid == 0) {
                (void) fclose(children);
                if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != parent)
                        _exit(EXIT_FAILURE);
                sigemptyset(&signals);
                if (sigprocmask(SIG_SETMASK, &signals, NULL) < 0)
                        _exit(EXIT_FAILURE);
                return 0;
        }

        for (;;) {
                pid_t reaped;
                int status, signal;

                while ((reaped = waitpid(-1, &status, WNOHANG)) > 0)
                        if (reaped == pid) {
                                if (!cancelled)
                                        result = WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE;
                                draining = true;
                        }
                if (reaped < 0) {
                        if (errno == ECHILD)
                                break;
                        if (errno == EINTR)
                                continue;
                        result = EXIT_FAILURE;
                        draining = true;
                }

                if (draining) {
                        struct timespec interval = { .tv_nsec = 100U * 1000000U };
                        int r;

                        r = kill_children(children);
                        if (r < 0 && !cleanup_error) {
                                fprintf(stderr, "Failed to terminate verification descendants: %s\n", strerror(-r));
                                cleanup_error = true;
                        }
                        /* procfs may omit children during concurrent exits. Only ECHILD completes cleanup. */
                        signal = sigtimedwait(&signals, NULL, &interval);
                } else
                        signal = sigwaitinfo(&signals, NULL);
                if (signal == SIGTERM || signal == SIGINT) {
                        cancelled = draining = true;
                        result = EXIT_FAILURE;
                }
        }

        (void) fclose(children);
        _exit(result);
}
