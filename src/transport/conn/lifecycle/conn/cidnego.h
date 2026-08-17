#ifndef CONN_CIDNEGO_H
#define CONN_CIDNEGO_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 7.2: a peer's Source Connection ID becomes the Destination
 * Connection ID we put on packets we send to it. */

/* Adopt peer SCID (<= 20 bytes) as our DCID (writes out->len). Returns 1 ok, 0
 * if too long. */
int cidnego_peer_dcid(wired_span peer_scid, wired_obuf* our_dcid);

/* Two connection IDs are equal iff same length and bytes. */
int cidnego_match(wired_span a, wired_span b);

#endif
