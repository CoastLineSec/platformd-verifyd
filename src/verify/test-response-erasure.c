/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG

#include "verify-util.h"

#include <assert.h>
#include <dlfcn.h>
#include <malloc.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>

#define TEST_RESPONSE "sensitive-test-response"

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer)
#define HAVE_ASAN 1
#else
#define HAVE_ASAN 0
#endif

typedef enum BufferKind {
        BUFFER_TRANSPORT,
        BUFFER_JSON,
        BUFFER_RESPONSE,
        _BUFFER_KIND_MAX,
} BufferKind;

typedef struct Buffer {
        void *data;
        size_t size;
        BufferKind kind;
} Buffer;

static Buffer buffers[32];
static unsigned observed[_BUFFER_KIND_MAX], erased[_BUFFER_KIND_MAX];
static pid_t client_pid;

static void observe(void *data, size_t size, BufferKind kind) {
        assert(data);
        assert(size > 0);

        for (size_t i = 0; i < sizeof buffers / sizeof buffers[0]; i++) {
                if (buffers[i].data)
                        continue;

                buffers[i] = (Buffer) { data, size, kind };
                observed[kind]++;
                return;
        }

        assert(false);
}

static void check_erased(void *p) {
        size_t size;

        if (!p || client_pid != getpid())
                return;

        size = malloc_usable_size(p);
        for (size_t i = 0; i < sizeof buffers / sizeof buffers[0]; i++) {
                uintptr_t start = (uintptr_t) buffers[i].data, allocation = (uintptr_t) p;
                const unsigned char *data = buffers[i].data;

                if (!data || start < allocation || start - allocation >= size)
                        continue;

                assert(buffers[i].size <= size - (start - allocation));
                for (size_t j = 0; j < buffers[i].size; j++)
                        assert(data[j] == 0);

                erased[buffers[i].kind]++;
                buffers[i] = (Buffer) {};
        }
}

#if HAVE_ASAN
void __sanitizer_free_hook(const volatile void *p) {
        check_erased((void *) p);
}
#else
void free(void *p) {
        static void (*next_free)(void *);
        static void *deferred[16];
        static size_t n_deferred;
        static bool resolving;

        if (!p)
                return;

        if (!next_free) {
                /* Resolving free() may release dynamic linker error state through this hook. */
                if (resolving) {
                        for (size_t i = 0; i < n_deferred; i++)
                                if (deferred[i] == p)
                                        return;
                        assert(n_deferred < sizeof deferred / sizeof deferred[0]);
                        deferred[n_deferred++] = p;
                        return;
                }

                resolving = true;
                next_free = dlsym(RTLD_NEXT, "free");
                assert(next_free);
                resolving = false;
                for (size_t i = 0; i < n_deferred; i++)
                        if (deferred[i] != p)
                                next_free(deferred[i]);
                n_deferred = 0;
        }

        check_erased(p);
        next_free(p);
}
#endif

ssize_t recvmsg(int fd, struct msghdr *message, int flags) {
        static ssize_t (*next_recvmsg)(int, struct msghdr *, int);
        ssize_t n;

        if (!next_recvmsg) {
                next_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
                assert(next_recvmsg);
        }

        n = next_recvmsg(fd, message, flags);
        if (n > 0 && client_pid == getpid()) {
                size_t remaining = (size_t) n;

                for (size_t i = 0; i < message->msg_iovlen && remaining > 0; i++) {
                        size_t size = message->msg_iov[i].iov_len;

                        if (size > remaining)
                                size = remaining;
                        if (memmem(message->msg_iov[i].iov_base, size, TEST_RESPONSE, strlen(TEST_RESPONSE)))
                                observe(message->msg_iov[i].iov_base, size, BUFFER_TRANSPORT);
                        remaining -= size;
                }
        }

        return n;
}

ssize_t read(int fd, void *buffer, size_t size) {
        static ssize_t (*next_read)(int, void *, size_t);
        ssize_t n;

        if (!next_read) {
                next_read = dlsym(RTLD_NEXT, "read");
                assert(next_read);
        }

        n = next_read(fd, buffer, size);
        if (n > 0 && client_pid == getpid() &&
            memmem(buffer, (size_t) n, TEST_RESPONSE, strlen(TEST_RESPONSE)))
                observe(buffer, (size_t) n, BUFFER_TRANSPORT);
        return n;
}

ssize_t recv(int fd, void *buffer, size_t size, int flags) {
        static ssize_t (*next_recv)(int, void *, size_t, int);
        ssize_t n;

        if (!next_recv) {
                next_recv = dlsym(RTLD_NEXT, "recv");
                assert(next_recv);
        }

        n = next_recv(fd, buffer, size, flags);
        if (n > 0 && client_pid == getpid() &&
            memmem(buffer, (size_t) n, TEST_RESPONSE, strlen(TEST_RESPONSE)))
                observe(buffer, (size_t) n, BUFFER_TRANSPORT);
        return n;
}

int __real_sd_varlink_call(sd_varlink *, const char *, sd_json_variant *, sd_json_variant **, const char **);

static void observe_json(sd_json_variant *v) {
        if (sd_json_variant_is_string(v)) {
                const char *s = sd_json_variant_string(v);

                if (strcmp(s, TEST_RESPONSE) == 0)
                        observe((char *) s, strlen(s), BUFFER_JSON);
        } else
                for (size_t i = 0; i < sd_json_variant_elements(v); i++)
                        observe_json(sd_json_variant_by_index(v, i));
}

int __wrap_sd_varlink_call(
                sd_varlink *link,
                const char *method,
                sd_json_variant *parameters,
                sd_json_variant **ret_parameters,
                const char **ret_error) {

        int r;

        r = __real_sd_varlink_call(link, method, parameters, ret_parameters, ret_error);
        if (*ret_parameters)
                observe_json(*ret_parameters);
        return r;
}

char *__real_strdup(const char *);

char *__wrap_strdup(const char *s) {
        char *p;

        p = __real_strdup(s);
        if (p && client_pid == getpid() && strcmp(s, TEST_RESPONSE) == 0)
                observe(p, strlen(p), BUFFER_RESPONSE);
        return p;
}

static void serve(int fd, const char *reply, bool terminate) {
        char request[4096];
        size_t used = 0, size = strlen(reply) + terminate;
        int connection;

        connection = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
        assert(connection >= 0);
        do {
                ssize_t n;

                assert(used < sizeof request);
                n = read(connection, request + used, sizeof request - used);
                assert(n > 0);
                used += (size_t) n;
        } while (!memchr(request, 0, used));

        while (size > 0) {
                ssize_t n = write(connection, reply, size);

                assert(n > 0);
                reply += n;
                size -= (size_t) n;
        }

        assert(close(connection) == 0);
        assert(close(fd) == 0);
        _exit(EXIT_SUCCESS);
}

static void test_response(
                const char *reply,
                bool terminate,
                bool echo,
                bool partial,
                int expected,
                bool parsed,
                bool copied) {

        struct sockaddr_un address = { .sun_family = AF_UNIX };
        const struct pam_message first = { echo ? PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF, "Password" };
        const struct pam_message second = { PAM_PROMPT_ECHO_OFF, "Invalid\nprompt" };
        const struct pam_message *messages[] = { &first, &second };
        VerifyConversationContext context = {
                .uid = getuid(),
                .timeout_usec = 1000000,
        };
        struct pam_response *responses = NULL;
        const char *runtime = getenv("XDG_RUNTIME_DIR");
        int fd, status, n;
        pid_t pid;

        assert(runtime);
        n = snprintf(address.sun_path, sizeof address.sun_path, "%s/response-erasure", runtime);
        assert(n > 0 && (size_t) n < sizeof address.sun_path);
        context.address = address.sun_path;
        memset(observed, 0, sizeof observed);
        memset(erased, 0, sizeof erased);

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        assert(fd >= 0);
        assert(bind(fd, (const struct sockaddr *) &address, sizeof address) == 0);
        assert(listen(fd, 1) == 0);

        pid = fork();
        assert(pid >= 0);
        if (pid == 0)
                serve(fd, reply, terminate);

        assert(close(fd) == 0);
        assert(verify_pam_conversation(partial ? 2 : 1, messages, &responses, &context) == expected);
        if (expected == PAM_SUCCESS) {
                assert(responses);
                assert(strcmp(responses[0].resp, TEST_RESPONSE) == 0);
                verify_pam_responses_erase(responses, 1);
        } else
                assert(!responses);

        assert(waitpid(pid, &status, 0) == pid);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
        assert(unlink(address.sun_path) == 0);

        assert(observed[BUFFER_TRANSPORT] > 0);
        assert((observed[BUFFER_JSON] > 0) == parsed);
        assert((observed[BUFFER_RESPONSE] > 0) == copied);
        for (BufferKind kind = 0; kind < _BUFFER_KIND_MAX; kind++)
                assert(observed[kind] == erased[kind]);
}

int main(void) {
        static const char success[] = "{\"parameters\":{\"passwords\":[\"" TEST_RESPONSE "\"]}}";

        client_pid = getpid();
        test_response(success, true, false, false, PAM_SUCCESS, true, true);
        test_response(success, true, true, false, PAM_SUCCESS, true, true);
        test_response(success, true, false, true, PAM_CONV_ERR, true, true);
        test_response("{\"parameters\":{\"passwords\":[\"" TEST_RESPONSE "\",\"other\"]}}",
                      true, false, false, PAM_CONV_ERR, true, false);
        test_response("{\"parameters\":{\"passwords\":\"" TEST_RESPONSE "\"}}",
                      true, false, false, PAM_CONV_ERR, true, false);
        test_response("{\"error\":\"io.systemd.AskPassword.NoPasswordAvailable\","
                      "\"parameters\":{\"passwords\":[\"" TEST_RESPONSE "\"]}}",
                      true, false, false, PAM_CONV_ERR, true, false);
        test_response("{\"parameters\":{\"passwords\":[\"" TEST_RESPONSE "\" invalid]}}",
                      true, false, false, PAM_CONV_ERR, false, false);
        test_response("{\"parameters\":{\"passwords\":[\"" TEST_RESPONSE "\"]}}",
                      false, false, false, PAM_CONV_ERR, false, false);
        return EXIT_SUCCESS;
}
