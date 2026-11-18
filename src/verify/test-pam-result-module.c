/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

static int request_password(pam_handle_t *pamh, const char *text) {
        const struct pam_message message = { PAM_PROMPT_ECHO_OFF, text };
        const struct pam_message *messages[] = { &message };
        struct pam_response *responses = NULL;
        const struct pam_conv *conversation;
        const void *item;
        int r;

        r = pam_get_item(pamh, PAM_CONV, &item);
        if (r != PAM_SUCCESS)
                return r;
        conversation = item;
        if (!conversation || !conversation->conv)
                return PAM_CONV_ERR;

        r = conversation->conv(1, messages, &responses, conversation->appdata_ptr);
        if (r == PAM_SUCCESS &&
            (!responses || responses[0].resp_retcode != 0 ||
             !responses[0].resp || strcmp(responses[0].resp, "test-password") != 0))
                r = PAM_AUTH_ERR;

        if (responses) {
                if (responses[0].resp) {
                        explicit_bzero(responses[0].resp, strlen(responses[0].resp));
                        free(responses[0].resp);
                }
                explicit_bzero(responses, sizeof *responses);
                free(responses);
        }

        return r;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        int r;

        if (argc == 1 && strcmp(argv[0], "permit") == 0)
                return PAM_SUCCESS;
        if (argc == 1 && strcmp(argv[0], "deny") == 0)
                return PAM_AUTH_ERR;
        if (argc == 1 && strcmp(argv[0], "messages") == 0) {
                const struct pam_conv *conversation;
                const struct pam_message message = { PAM_TEXT_INFO, "message limit test" };
                const struct pam_message *messages[] = { &message };

                if (pam_get_item(pamh, PAM_CONV, (const void **) &conversation) != PAM_SUCCESS)
                        return PAM_SERVICE_ERR;
                for (unsigned i = 0; i < 33; i++) {
                        struct pam_response *response = NULL;

                        (void) conversation->conv(1, messages, &response, conversation->appdata_ptr);
                        free(response);
                }
                return PAM_SUCCESS;
        }
        if (argc != 2)
                return PAM_SERVICE_ERR;

        if (strcmp(argv[0], "prompt") == 0)
                return request_password(pamh, argv[1]);
        if (strcmp(argv[0], "retry") != 0)
                return PAM_SERVICE_ERR;

        r = request_password(pamh, argv[1]);
        if (r != PAM_CONV_ERR)
                return PAM_SERVICE_ERR;

        return request_password(pamh, "Password");
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return PAM_SUCCESS;
}
