/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <security/pam_modules.h>
#include <systemd/sd-journal.h>

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        const struct pam_conv *conversation;
        const struct pam_message message = { PAM_TEXT_INFO, "worker-exec-conversation" };
        const struct pam_message *messages[] = { &message };
        struct pam_response *responses = NULL;
        int r;
        DIR *directory;
        struct dirent *entry;
        unsigned channels = 0;

        directory = opendir("/proc/self/fd");
        if (!directory)
                return PAM_SYSTEM_ERR;
        while ((entry = readdir(directory))) {
                int fd = atoi(entry->d_name), type;
                socklen_t size = sizeof type;

                if (fd < 3 || getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) < 0 || type != SOCK_SEQPACKET)
                        continue;
                if (!(fcntl(fd, F_GETFD) & FD_CLOEXEC)) {
                        closedir(directory);
                        return PAM_SYSTEM_ERR;
                }
                channels++;
        }
        closedir(directory);
        if (channels != 1)
                return PAM_SYSTEM_ERR;

        if (sd_journal_print(LOG_DEBUG, "worker-exec-module") < 0)
                return PAM_SYSTEM_ERR;
        r = pam_get_item(pamh, PAM_CONV, (const void **) &conversation);
        if (r != PAM_SUCCESS || !conversation)
                return PAM_SYSTEM_ERR;
        r = conversation->conv(1, messages, &responses, conversation->appdata_ptr);
        if (responses) {
                free(responses[0].resp);
                free(responses);
        }
        return r;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return PAM_SUCCESS;
}
