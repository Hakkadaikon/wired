#ifndef QUIC_INITPKT_INITOPEN_H
#define QUIC_INITPKT_INITOPEN_H

#include "common/bytes/span/span.h"
#include "transport/version/version/version.h"

/* RFC 9001 5.2: open an AEAD-protected Initial packet built by
 * quic_initpkt_build. Re-derives the Initial keys from dcid, removes header
 * protection, and AEAD-opens the payload in place. On success *crypto views
 * the recovered frame bytes within pkt. Returns 1 on success, 0 on
 * authentication failure or short input. Equivalent to
 * quic_initpkt_open_ver(dcid, QUIC_VERSION_1, pkt, crypto). */
int quic_initpkt_open(quic_span dcid, quic_mspan pkt, quic_span* crypto);

/* RFC 9001 5.2 / RFC 9369 3.3.1: same as quic_initpkt_open, but deriving
 * Initial keys under the given version (the long header's own Version
 * field) instead of assuming v1 -- what a server's accept path needs for a
 * peer that arrived already speaking v2. */
int quic_initpkt_open_ver(
    quic_span dcid, u32 version, quic_mspan pkt, quic_span* crypto);

#endif
