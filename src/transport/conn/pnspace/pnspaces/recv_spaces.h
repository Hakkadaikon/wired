#ifndef PNSPACES_RECV_SPACES_H
#define PNSPACES_RECV_SPACES_H

#include "common/platform/sys/syscall.h"
#include "transport/conn/lifecycle/conn/pnspace.h"
#include "transport/conn/pnspace/recvpn/recvpn.h"
#include "transport/recovery/detect/ackgen/ackrange.h"

/* RFC 9000 13.1: each packet number space independently records the packet
 * numbers it has received and builds its own ACK ranges from them. */

/* Holds largest + the window below it, so at most window+1 received PNs feed
 * the ACK-range builder. */
#define PNSPACES_ACK_CAP (RECVPN_WINDOW + 1)

/** Per-space received-packet-number tracking (recvpn), one per
 * PNS_*. */
typedef struct {
  recvpn r[PNS_COUNT]; /**< indexed by PNS_INITIAL/HANDSHAKE/APP */
} pnspaces_recv;

void pnspaces_recv_init(pnspaces_recv* s);

/* Record packet number pn as received in `space` only. */
void pnspaces_on_recv(pnspaces_recv* s, int space, u64 pn);

/** Where pnspaces_ack_ranges writes the largest acked and the ranges. */
typedef struct {
  u64*     largest; /**< out: highest received packet number in `space` */
  u64obuf* ranges;  /**< out: encoded ACK ranges, see ackgen_build_ranges */
} pnspaces_ack_out;

/* Build the ACK ranges for `space` from its received PNs (layout per
 * ackgen_build_ranges / RFC 9000 19.3). Returns 1 on success, 0 if the
 * space has received nothing or cap is too small. */
int pnspaces_ack_ranges(
    const pnspaces_recv* s, int space, const pnspaces_ack_out* out);

#endif
