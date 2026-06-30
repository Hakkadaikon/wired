#ifndef QUIC_CONN_DEMUX_H
#define QUIC_CONN_DEMUX_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 5.1/5.2: route an incoming packet to a connection by its
 * Destination Connection ID. Returns 1 if the packet's DCID exactly matches
 * the connection's CID (same length and bytes), 0 otherwise. Zero-length CIDs
 * match only other zero-length CIDs. */
int quic_demux_match(const u8 *dcid, usz dcid_len,
                     const u8 *conn_cid, usz cid_len);

#endif
