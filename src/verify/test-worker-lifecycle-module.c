/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <security/pam_modules.h>

static int record_pid(const char *directory, const char *name) {
        char *path;
        FILE *f;
        int r;

        if (asprintf(&path, "%s/%s", directory, name) < 0)
                return -ENOMEM;
        f = fopen(path, "we");
        free(path);
        if (!f)
                return -errno;
        r = fprintf(f, "%ld\n", (long) getpid()) < 0 ? -EIO : 0;
        if (fclose(f) < 0)
                return -errno;
        return r;
}

static void linger(const char *directory, const char *name) {
        if (signal(SIGTERM, SIG_IGN) == SIG_ERR || signal(SIGINT, SIG_IGN) == SIG_ERR ||
            record_pid(directory, name) < 0)
                _exit(EXIT_FAILURE);
        for (;;)
                pause();
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        char *release;
        pid_t pid;
        int status;

        if (argc != 1 || argv[0][0] != '/' || record_pid(argv[0], "worker") < 0)
                return PAM_SERVICE_ERR;

        pid = fork();
        if (pid < 0)
                return PAM_SERVICE_ERR;
        if (pid == 0)
                linger(argv[0], "direct");

        pid = fork();
        if (pid < 0)
                return PAM_SERVICE_ERR;
        if (pid == 0) {
                if (setsid() < 0)
                        _exit(EXIT_FAILURE);
                pid = fork();
                if (pid < 0)
                        _exit(EXIT_FAILURE);
                if (pid > 0)
                        _exit(EXIT_SUCCESS);
                linger(argv[0], "detached");
        }
        while (waitpid(pid, &status, 0) < 0)
                if (errno != EINTR)
                        return PAM_SERVICE_ERR;
        if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS)
                return PAM_SERVICE_ERR;

        if (asprintf(&release, "%s/release", argv[0]) < 0)
                return PAM_BUF_ERR;
        while (access(release, F_OK) < 0) {
                if (errno != ENOENT) {
                        free(release);
                        return PAM_SERVICE_ERR;
                }
                usleep(10000);
        }
        free(release);
        return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return PAM_SUCCESS;
}
