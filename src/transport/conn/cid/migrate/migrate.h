#ifndef QUIC_MIGRATE_MIGRATE_H
#define QUIC_MIGRATE_MIGRATE_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 9: connection migration on top of path validation. A new path is
 * confirmed only after the peer's address change is detected, a
 * PATH_CHALLENGE is sent, and the path validates. Confirming a full
 * migration switches to an unused connection ID (retiring the old one) and
 * resets congestion control and RTT; a port-only change keeps them. */

typedef struct {
    int handshake_confirmed;
    int detected;
    int challenged;
    int validated;
    int confirmed;
    u64 cur_cid;
    int cc_reset;
    int port_only;
} quic_migrate;

void quic_migrate_init(quic_migrate *m, u64 cid);
void quic_migrate_detect(quic_migrate *m);
void quic_migrate_challenge(quic_migrate *m);
int quic_migrate_validate(quic_migrate *m);
int quic_migrate_confirm(quic_migrate *m, u64 new_cid, int port_only);

#endif
