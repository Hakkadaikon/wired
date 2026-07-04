#ifndef QUIC_CONN_CIDNEGO_H
#define QUIC_CONN_CIDNEGO_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 7.2: a peer's Source Connection ID becomes the Destination
 * Connection ID we put on packets we send to it. */

/* Adopt peer SCID (<= 20 bytes) as our DCID (writes out->len). Returns 1 ok, 0
 * if too long. */
int quic_cidnego_peer_dcid(quic_span peer_scid, quic_obuf* our_dcid);

/* Two connection IDs are equal iff same length and bytes. */
int quic_cidnego_match(quic_span a, quic_span b);

#endif
