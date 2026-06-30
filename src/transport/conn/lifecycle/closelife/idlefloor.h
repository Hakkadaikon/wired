#ifndef QUIC_CLOSELIFE_IDLEFLOOR_H
#define QUIC_CLOSELIFE_IDLEFLOOR_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 10.1: idle timeout must not undercut 3*PTO. */

u64 quic_idle_floor(u64 idle_timeout, u64 pto);
int quic_idle_should_close(u64 elapsed, u64 effective_idle);

#endif
