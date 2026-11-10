#ifndef POLL_NONBLOCK_H
#define POLL_NONBLOCK_H

#include "common/platform/sys/syscall.h"

#define O_NONBLOCK 0x800 /* O_NONBLOCK */
#define F_SETFL 4        /* fcntl cmd F_SETFL */

/* fcntl(fd, F_SETFL, O_NONBLOCK). Returns 0 or a negative errno. */
i64 poll_set_nonblock(i64 fd);

#endif
