#ifndef QUIC_CONN_DEMUX_H
#define QUIC_CONN_DEMUX_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 5.1/5.2: route an incoming packet to a connection by its
 * Destination Connection ID. Returns 1 if the packet's DCID exactly matches
 * the connection's CID (same length and bytes), 0 otherwise. Zero-length CIDs
 * match only other zero-length CIDs. */
int quic_demux_match(quic_span dcid, quic_span conn_cid);

#endif
