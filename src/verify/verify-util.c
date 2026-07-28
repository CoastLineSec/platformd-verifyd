/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "verify-util.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <systemd/sd-journal.h>
#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>

#define streq(a, b) (strcmp((a), (b)) == 0)
#define _cleanup_(f) __attribute__((cleanup(f)))
static inline void freep(void *p) { free(*(void **) p); }
#define _cleanup_free_ _cleanup_(freep)

#define VERIFY_RESPONSE_MAX (64U * 1024U)

bool verify_text_valid(const char *text, size_t max) {
        size_t n;

        if (!text)
                return false;

        n = strnlen(text, max + 1);
        if (n > max)
                return false;

        for (size_t i = 0; i < n; i++)
                if ((unsigned char) text[i] < 0x20 || (unsigned char) text[i] == 0x7f)
                        return false;

        return true;
}

bool verify_session_class_allowed(const char *class) {
        return class &&
               (streq(class, "user") ||
                streq(class, "user-early") ||
                streq(class, "user-light") ||
                streq(class, "user-early-light"));
}

void verify_erase_string(char *s) {
        if (!s)
                return;

        explicit_bzero(s, strlen(s));
        free(s);
}

void verify_pam_responses_erase(struct pam_response *responses, size_t n) {
        if (!responses)
                return;

        for (size_t i = 0; i < n; i++)
                verify_erase_string(responses[i].resp);
        explicit_bzero(responses, n * sizeof *responses);
        free(responses);
}

static int ask_password(
                VerifyConversationContext *context,
                const char *prompt,
                bool echo,
                char **ret) {

        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        _cleanup_free_ char *address = NULL, *id = NULL, *message = NULL;
        const char *error_id = NULL, *response;
        sd_json_variant *passwords, *entry, *reply = NULL;
        int r;

        *ret = NULL;

        if (!verify_text_valid(prompt, VERIFY_PAM_MESSAGE_MAX)) {
                context->prompt_status = VERIFY_PROMPT_PROTOCOL_ERROR;
                return -EINVAL;
        }

        if (context->address) {
                address = strdup(context->address);
                if (!address)
                        return -ENOMEM;
        } else if (asprintf(&address, "/run/user/%u/systemd/io.systemd.AskPassword",
                            (unsigned) context->uid) < 0)
                return -ENOMEM;

        if (asprintf(&id, "platformd-verifyd:%u:%ld:%u",
                     (unsigned) context->uid, (long) getpid(), context->sequence++) < 0)
                return -ENOMEM;

        if (context->reason && *context->reason) {
                if (asprintf(&message,
                             "Authentication is required by platformd-verifyd. "
                             "%s Request description: %s",
                             prompt, context->reason) < 0)
                        return -ENOMEM;
        } else if (asprintf(&message,
                            "Authentication is required by platformd-verifyd. %s",
                            prompt) < 0)
                return -ENOMEM;

        r = sd_json_buildo(&parameters,
                SD_JSON_BUILD_PAIR("message", SD_JSON_BUILD_STRING(message)),
                SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_STRING(id)),
                SD_JSON_BUILD_PAIR("timeoutUSec", SD_JSON_BUILD_UNSIGNED(context->timeout_usec)),
                SD_JSON_BUILD_PAIR("acceptCached", SD_JSON_BUILD_BOOLEAN(false)),
                SD_JSON_BUILD_PAIR("pushCache", SD_JSON_BUILD_BOOLEAN(false)),
                SD_JSON_BUILD_PAIR("echo", SD_JSON_BUILD_STRING(echo ? "on" : "off")),
                SD_JSON_BUILD_PAIR("allowInteractiveAuthentication", SD_JSON_BUILD_BOOLEAN(false)));
        if (r < 0)
                return r;

        r = sd_varlink_connect_address(&link, address);
        if (r < 0) {
                context->prompt_status = VERIFY_PROMPT_UNAVAILABLE;
                return r;
        }

        r = sd_varlink_call(link, "io.systemd.AskPassword.Ask",
                            parameters, &reply, &error_id);
        if (reply)
                sd_json_variant_sensitive(reply);
        if (r < 0) {
                context->prompt_status = VERIFY_PROMPT_UNAVAILABLE;
                return r;
        }
        if (error_id) {
                if (streq(error_id, "io.systemd.AskPassword.TimeoutReached"))
                        context->prompt_status = VERIFY_PROMPT_TIMED_OUT;
                else if (streq(error_id, "io.systemd.AskPassword.NoPasswordAvailable"))
                        context->prompt_status = VERIFY_PROMPT_UNAVAILABLE;
                else
                        context->prompt_status = VERIFY_PROMPT_UNAVAILABLE;
                return -EIO;
        }

        passwords = reply ? sd_json_variant_by_key(reply, "passwords") : NULL;
        if (!passwords || !sd_json_variant_is_array(passwords) ||
            sd_json_variant_elements(passwords) != 1) {
                context->prompt_status = VERIFY_PROMPT_PROTOCOL_ERROR;
                return -EPROTO;
        }

        entry = sd_json_variant_by_index(passwords, 0);
        if (!entry || !sd_json_variant_is_string(entry)) {
                context->prompt_status = VERIFY_PROMPT_PROTOCOL_ERROR;
                return -EPROTO;
        }

        response = sd_json_variant_string(entry);
        if (strnlen(response, VERIFY_RESPONSE_MAX + 1) > VERIFY_RESPONSE_MAX) {
                context->prompt_status = VERIFY_PROMPT_PROTOCOL_ERROR;
                return -E2BIG;
        }

        *ret = strdup(response);
        if (!*ret)
                return -ENOMEM;
        return 0;
}

int verify_pam_conversation(
                int n_messages,
                const struct pam_message **messages,
                struct pam_response **ret_responses,
                void *userdata) {

        VerifyConversationContext *context = userdata;
        struct pam_response *responses;
        int r;

        if (!context || !ret_responses || n_messages <= 0 || !messages)
                return PAM_CONV_ERR;

        responses = calloc((size_t) n_messages, sizeof *responses);
        if (!responses)
                return PAM_BUF_ERR;

        for (int i = 0; i < n_messages; i++) {
                const char *text;

                if (!messages[i]) {
                        r = PAM_CONV_ERR;
                        goto fail;
                }

                text = messages[i]->msg ?: "";
                switch (messages[i]->msg_style) {
                case PAM_PROMPT_ECHO_OFF:
                case PAM_PROMPT_ECHO_ON:
                        r = ask_password(context, text,
                                         messages[i]->msg_style == PAM_PROMPT_ECHO_ON,
                                         &responses[i].resp);
                        if (r < 0) {
                                r = r == -ENOMEM ? PAM_BUF_ERR : PAM_CONV_ERR;
                                goto fail;
                        }
                        break;
                case PAM_TEXT_INFO:
                case PAM_ERROR_MSG:
                        if (!verify_text_valid(text, VERIFY_PAM_MESSAGE_MAX)) {
                                context->prompt_status = VERIFY_PROMPT_PROTOCOL_ERROR;
                                r = PAM_CONV_ERR;
                                goto fail;
                        }
                        sd_journal_print(messages[i]->msg_style == PAM_ERROR_MSG ? LOG_NOTICE : LOG_INFO,
                                         "pam: %s", text);
                        break;
                default:
                        context->prompt_status = VERIFY_PROMPT_PROTOCOL_ERROR;
                        r = PAM_CONV_ERR;
                        goto fail;
                }
        }

        *ret_responses = responses;
        return PAM_SUCCESS;

fail:
        verify_pam_responses_erase(responses, (size_t) n_messages);
        return r;
}
