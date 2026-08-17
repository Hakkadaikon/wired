#ifndef CLOSELIFE_IDLEFLOOR_H
#define CLOSELIFE_IDLEFLOOR_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 10.1: idle timeout must not undercut 3*PTO. */

u64 idle_floor(u64 idle_timeout, u64 pto);
int idle_should_close(u64 elapsed, u64 effective_idle);

#endif
