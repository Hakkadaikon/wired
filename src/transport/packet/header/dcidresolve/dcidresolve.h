#ifndef QUIC_PACKET_DCIDRESOLVE_H
#define QUIC_PACKET_DCIDRESOLVE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * RFC 9000 5.1/17.2/17.3: extract a received datagram's Destination
 * Connection ID without a full header parse, so a multi-connection server can
 * route it to the right slot before spending a real parse on it. A long
 * header carries its DCID length at byte 5; a short header (1-RTT) carries
 * none, so the caller supplies the server's own fixed local CID length. */

/** The Destination Connection ID length dg claims.
 * @param dg the received datagram
 * @param short_hdr_len the server's own fixed CID length, used for a short
 *   header (which carries no length prefix)
 * @return the DCID length, or -1 if dg is too short to carry the length it
 *   claims (a long header needs 6 bytes just to reach the length byte). */
int quic_dcidresolve_len(quic_mspan dg, u8 short_hdr_len);

/** The DCID as a span into dg. dcid_len is normally quic_dcidresolve_len's
 * result; a negative dcid_len or one that does not fit within dg yields a
 * 0-length span (indistinguishable from a legitimate zero-length CID, RFC
 * 9000 5.1 — callers that must tell these apart check dcid_len < 0 first). */
quic_span quic_dcidresolve_dcid(quic_mspan dg, int dcid_len);

#endif
