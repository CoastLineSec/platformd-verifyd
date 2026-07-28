/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "verify-util.h"

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <systemd/sd-event.h>
#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>

static int method_ask(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        sd_json_variant *v;
        const char *echo, *message;

        v = sd_json_variant_by_key(parameters, "acceptCached");
        if (!v || !sd_json_variant_is_boolean(v) || sd_json_variant_boolean(v))
                return sd_varlink_error(link, "io.test.InvalidRequest", NULL);
        v = sd_json_variant_by_key(parameters, "pushCache");
        if (!v || !sd_json_variant_is_boolean(v) || sd_json_variant_boolean(v))
                return sd_varlink_error(link, "io.test.InvalidRequest", NULL);
        v = sd_json_variant_by_key(parameters, "allowInteractiveAuthentication");
        if (!v || !sd_json_variant_is_boolean(v) || sd_json_variant_boolean(v))
                return sd_varlink_error(link, "io.test.InvalidRequest", NULL);
        v = sd_json_variant_by_key(parameters, "echo");
        if (!v || !sd_json_variant_is_string(v))
                return sd_varlink_error(link, "io.test.InvalidRequest", NULL);
        echo = sd_json_variant_string(v);
        if (strcmp(echo, "off") != 0 && strcmp(echo, "on") != 0)
                return sd_varlink_error(link, "io.test.InvalidRequest", NULL);
        if (sd_json_variant_by_key(parameters, "keyname"))
                return sd_varlink_error(link, "io.test.InvalidRequest", NULL);
        v = sd_json_variant_by_key(parameters, "message");
        if (!v || !sd_json_variant_is_string(v))
                return sd_varlink_error(link, "io.test.InvalidRequest", NULL);
        message = sd_json_variant_string(v);
        if (!strstr(message, "Authentication is required by platformd-verifyd.") ||
            !strstr(message, "Request description: test request"))
                return sd_varlink_error(link, "io.test.InvalidRequest", NULL);
        if (strstr(message, "Timeout"))
                return sd_varlink_error(
                                link, "io.systemd.AskPassword.TimeoutReached", NULL);
        if (strstr(message, "Unavailable"))
                return sd_varlink_error(
                                link, "io.systemd.AskPassword.NoPasswordAvailable", NULL);
        if (strstr(message, "Multiple"))
                return sd_varlink_replybo(
                                link,
                                SD_JSON_BUILD_PAIR(
                                                "passwords",
                                                SD_JSON_BUILD_ARRAY(
                                                                SD_JSON_BUILD_STRING("one"),
                                                                SD_JSON_BUILD_STRING("two"))));

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR(
                                        "passwords",
                                        SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_STRING("test-password"))));
}

static void run_server(const char *path) {
        sd_varlink_server *server = NULL;
        sd_event *event = NULL;

        assert(sd_event_default(&event) >= 0);
        assert(sd_varlink_server_new(&server, 0) >= 0);
        assert(sd_varlink_server_bind_method(
                               server, "io.systemd.AskPassword.Ask", method_ask) >= 0);
        assert(sd_varlink_server_listen_address(server, path, 0600) >= 0);
        assert(sd_varlink_server_attach_event(server, event, 0) >= 0);
        (void) sd_event_loop(event);
        sd_varlink_server_unref(server);
        sd_event_unref(event);
        _exit(EXIT_SUCCESS);
}

int main(void) {
        const struct pam_message m0 = { PAM_PROMPT_ECHO_OFF, "Password" };
        const struct pam_message m1 = { PAM_TEXT_INFO, "Authentication test" };
        const struct pam_message m2 = { PAM_PROMPT_ECHO_ON, "PIN" };
        const struct pam_message *messages[] = { &m0, &m1, &m2 };
        struct pam_response *responses = NULL;
        char template[] = "/tmp/platformd-verifyd-test-XXXXXX";
        char socket[sizeof template + 32];
        VerifyConversationContext context = {
                .reason = "test request",
                .uid = getuid(),
                .timeout_usec = 5 * 1000000ULL,
        };
        char *dir;
        pid_t pid;

        assert(verify_text_valid("", VERIFY_REASON_MAX));
        assert(verify_text_valid("valid reason", VERIFY_REASON_MAX));
        assert(!verify_text_valid("invalid\nreason", VERIFY_REASON_MAX));
        {
                char overlong[VERIFY_SESSION_MAX + 2];

                memset(overlong, 'x', sizeof overlong);
                overlong[sizeof overlong - 1] = 0;
                assert(!verify_text_valid(overlong, VERIFY_SESSION_MAX));
        }
        assert(verify_session_class_allowed("user"));
        assert(verify_session_class_allowed("user-light"));
        assert(!verify_session_class_allowed("greeter"));
        assert(!verify_session_class_allowed("user-incomplete"));

        dir = mkdtemp(template);
        assert(dir);
        assert(snprintf(socket, sizeof socket, "%s/ask-password", dir) > 0);
        context.address = socket;

        pid = fork();
        assert(pid >= 0);
        if (pid == 0)
                run_server(socket);

        for (unsigned i = 0; i < 500 && access(socket, F_OK) < 0; i++)
                usleep(10000);
        assert(access(socket, F_OK) == 0);

        assert(verify_pam_conversation(3, messages, &responses, &context) == PAM_SUCCESS);
        assert(responses);
        assert(responses[0].resp && strcmp(responses[0].resp, "test-password") == 0);
        assert(!responses[1].resp);
        assert(responses[2].resp && strcmp(responses[2].resp, "test-password") == 0);
        verify_pam_responses_erase(responses, 3);
        responses = NULL;

        {
                const struct pam_message timeout_message = {
                        PAM_PROMPT_ECHO_OFF,
                        "Timeout",
                };
                const struct pam_message *one[] = { &timeout_message };

                context.prompt_status = VERIFY_PROMPT_NONE;
                assert(verify_pam_conversation(1, one, &responses, &context) == PAM_CONV_ERR);
                assert(context.prompt_status == VERIFY_PROMPT_TIMED_OUT);
                assert(!responses);
        }

        {
                const struct pam_message unavailable_message = {
                        PAM_PROMPT_ECHO_OFF,
                        "Unavailable",
                };
                const struct pam_message *one[] = { &unavailable_message };

                context.prompt_status = VERIFY_PROMPT_NONE;
                assert(verify_pam_conversation(1, one, &responses, &context) == PAM_CONV_ERR);
                assert(context.prompt_status == VERIFY_PROMPT_UNAVAILABLE);
                assert(!responses);
        }

        {
                const struct pam_message multiple_message = {
                        PAM_PROMPT_ECHO_OFF,
                        "Multiple",
                };
                const struct pam_message *one[] = { &multiple_message };

                context.prompt_status = VERIFY_PROMPT_NONE;
                assert(verify_pam_conversation(1, one, &responses, &context) == PAM_CONV_ERR);
                assert(context.prompt_status == VERIFY_PROMPT_PROTOCOL_ERROR);
                assert(!responses);
        }

        {
                const struct pam_message valid_message = {
                        PAM_PROMPT_ECHO_OFF,
                        "Password",
                };
                const struct pam_message invalid_message = {
                        PAM_PROMPT_ECHO_OFF,
                        "Invalid\nprompt",
                };
                const struct pam_message *partial[] = {
                        &valid_message,
                        &invalid_message,
                };

                context.prompt_status = VERIFY_PROMPT_NONE;
                assert(verify_pam_conversation(
                                       2, partial, &responses, &context) == PAM_CONV_ERR);
                assert(context.prompt_status == VERIFY_PROMPT_PROTOCOL_ERROR);
                assert(!responses);
        }

        assert(kill(pid, SIGTERM) >= 0);
        assert(waitpid(pid, NULL, 0) == pid);
        (void) unlink(socket);
        assert(rmdir(dir) >= 0);
        return EXIT_SUCCESS;
}
