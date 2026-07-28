/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include <security/pam_appl.h>

#define VERIFY_REASON_MAX 256
#define VERIFY_SESSION_MAX 256
#define VERIFY_PAM_MESSAGE_MAX 1024

typedef enum VerifyPromptStatus {
        VERIFY_PROMPT_NONE,
        VERIFY_PROMPT_UNAVAILABLE,
        VERIFY_PROMPT_TIMED_OUT,
        VERIFY_PROMPT_CANCELLED,
        VERIFY_PROMPT_PROTOCOL_ERROR,
} VerifyPromptStatus;

typedef struct VerifyConversationContext {
        const char *address;
        const char *reason;
        uid_t uid;
        uint64_t timeout_usec;
        unsigned sequence;
        VerifyPromptStatus prompt_status;
} VerifyConversationContext;

bool verify_text_valid(const char *text, size_t max);
bool verify_session_class_allowed(const char *class);
void verify_erase_string(char *s);
void verify_pam_responses_erase(struct pam_response *responses, size_t n);
int verify_pam_conversation(
                int n_messages,
                const struct pam_message **messages,
                struct pam_response **ret_responses,
                void *userdata);
