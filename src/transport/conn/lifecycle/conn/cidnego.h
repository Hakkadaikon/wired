#ifndef QUIC_CONN_CIDNEGO_H
#define QUIC_CONN_CIDNEGO_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 7.2: a peer's Source Connection ID becomes the Destination
 * Connection ID we put on packets we send to it. */

/* Adopt peer SCID (<= 20 bytes) as our DCID. Returns 1 ok, 0 if too long. */
int quic_cidnego_peer_dcid(const u8 *peer_scid, usz scid_len,
                           u8 *our_dcid, usz *our_dcid_len);

/* Two connection IDs are equal iff same length and bytes. */
int quic_cidnego_match(const u8 *a, usz a_len, const u8 *b, usz b_len);

#endif
