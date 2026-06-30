#ifndef QUIC_PNSPACES_RECV_SPACES_H
#define QUIC_PNSPACES_RECV_SPACES_H

#include "common/platform/sys/syscall.h"
#include "transport/conn/lifecycle/conn/pnspace.h"
#include "transport/conn/pnspace/recvpn/recvpn.h"

/* RFC 9000 13.1: each packet number space independently records the packet
 * numbers it has received and builds its own ACK ranges from them. */

/* Holds largest + the window below it, so at most window+1 received PNs feed
 * the ACK-range builder. */
#define QUIC_PNSPACES_ACK_CAP (QUIC_RECVPN_WINDOW + 1)

typedef struct {
    quic_recvpn r[QUIC_PNS_COUNT];
} quic_pnspaces_recv;

void quic_pnspaces_recv_init(quic_pnspaces_recv *s);

/* Record packet number pn as received in `space` only. */
void quic_pnspaces_on_recv(quic_pnspaces_recv *s, int space, u64 pn);

/* Build the ACK ranges for `space` from its received PNs (layout per
 * quic_ackgen_build_ranges / RFC 9000 19.3). Returns 1 on success, 0 if the
 * space has received nothing or cap is too small. */
int quic_pnspaces_ack_ranges(const quic_pnspaces_recv *s, int space,
                             u64 *largest, u64 *ranges, usz *n_ranges, usz cap);

#endif
