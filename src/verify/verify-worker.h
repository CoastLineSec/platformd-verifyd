/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

/* Returns the supervisor PID, zero in the worker, or a negative errno.
 * Signal the supervisor with SIGTERM; normal exit follows descendant cleanup.
 * preserve_fd is inherited only by the worker; pass -1 to close all non-stdio descriptors. */
pid_t verify_worker_fork(int preserve_fd);
