/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

/* Returns the supervisor PID, zero in the worker, or a negative errno.
 * Signal the supervisor with SIGTERM; normal exit follows descendant cleanup. */
pid_t verify_worker_fork(void);
