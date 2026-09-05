/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include <security/pam_modules.h>
#include <systemd/sd-journal.h>

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        const struct pam_conv *conversation;
        const struct pam_message message = { PAM_TEXT_INFO, "worker-exec-conversation" };
        const struct pam_message *messages[] = { &message };
        struct pam_response *responses = NULL;
        int r;

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
