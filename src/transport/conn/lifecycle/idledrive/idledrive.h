#ifndef QUIC_IDLEDRIVE_IDLEDRIVE_H
#define QUIC_IDLEDRIVE_IDLEDRIVE_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 10.1: stateful idle-timeout driver. Holds the effective timeout and
 * the timestamp of the last packet sent or received; fires once enough time has
 * elapsed since that activity. */

/** RFC 9000 10.1: idle-timeout state -- the effective timeout and the time of
 * last send/recv activity. */
typedef struct {
  u64 idle_timeout;  /* effective idle timeout; 0 disables */
  u64 last_activity; /* time of last send/recv */
} idledrive;

void idledrive_init(idledrive* s, u64 idle_timeout);

/* A packet was sent or received at time now: refresh the activity timestamp. */
void idledrive_on_activity(idledrive* s, u64 now);

/* 1 iff a non-zero timeout has elapsed since the last activity. */
int idledrive_expired(const idledrive* s, u64 now);

#endif
