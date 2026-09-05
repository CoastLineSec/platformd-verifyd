/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#define main verifyd_main
#include "verifyd.c"
#undef main

#include <assert.h>
#include <dlfcn.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>

static struct sockaddr_un journal_address(void) {
        struct sockaddr_un address = { .sun_family = AF_UNIX };
        const char *runtime = getenv("XDG_RUNTIME_DIR");
        int n;

        assert(runtime);
        n = snprintf(address.sun_path, sizeof address.sun_path, "%s/worker-journal", runtime);
        assert(n > 0 && (size_t) n < sizeof address.sun_path);
        return address;
}

ssize_t sendmsg(int fd, const struct msghdr *message, int flags) {
        static ssize_t (*next_sendmsg)(int, const struct msghdr *, int);
        const struct sockaddr_un *destination = message->msg_name;
        struct sockaddr_un address;
        struct msghdr redirected;

        if (!next_sendmsg) {
                next_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
                assert(next_sendmsg);
        }

        if (destination && message->msg_namelen >= sizeof(sa_family_t) &&
            destination->sun_family == AF_UNIX &&
            strcmp(destination->sun_path, "/run/systemd/journal/socket") == 0) {
                address = journal_address();
                redirected = *message;
                redirected.msg_name = &address;
                redirected.msg_namelen = sizeof address;
                message = &redirected;
        }

        return next_sendmsg(fd, message, flags);
}

static int receive_journal(void) {
        struct sockaddr_un address = journal_address();
        bool module = false, conversation = false, requested = false;
        struct pollfd pollfd;
        char message[8192];
        int fd;

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        assert(fd >= 0);
        assert(bind(fd, (const struct sockaddr *) &address, sizeof address) == 0);
        pollfd = (struct pollfd) { .fd = fd, .events = POLLIN };

        while (!module || !conversation || !requested) {
                ssize_t n;

                assert(poll(&pollfd, 1, 5000) > 0);
                n = recv(fd, message, sizeof message - 1, 0);
                assert(n > 0);
                message[n] = 0;
                module |= strstr(message, "MESSAGE=worker-exec-module\n") != NULL;
                conversation |= strstr(message, "MESSAGE=pam: worker-exec-conversation\n") != NULL;
                requested |= strstr(message, "PLATFORMD_EVENT=verify-request\n") != NULL;
        }

        assert(close(fd) == 0);
        assert(unlink(address.sun_path) == 0);
        return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
        if (argc == 2 && strcmp(argv[1], "--test-journal") == 0)
                return receive_journal();
        return verifyd_main(argc, argv);
}
