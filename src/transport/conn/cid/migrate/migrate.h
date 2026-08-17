#ifndef MIGRATE_MIGRATE_H
#define MIGRATE_MIGRATE_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 9: connection migration on top of path validation. A new path is
 * confirmed only after the peer's address change is detected, a
 * PATH_CHALLENGE is sent, and the path validates. Confirming a full
 * migration switches to an unused connection ID (retiring the old one) and
 * resets congestion control and RTT; a port-only change keeps them. */

/** RFC 9000 9: connection migration state -- the path-validation progress
 * (detected/challenged/validated/confirmed), the current connection ID, and
 * whether congestion control was reset for a full (non-port-only) migration. */
typedef struct {
  int handshake_confirmed;
  int detected;
  int challenged;
  int validated;
  int confirmed;
  u64 cur_cid;
  int cc_reset;
  int port_only;
} migrate;

void migrate_init(migrate* m, u64 cid);
void migrate_detect(migrate* m);
void migrate_challenge(migrate* m);
int  migrate_validate(migrate* m);
int  migrate_confirm(migrate* m, u64 new_cid, int port_only);

#endif
