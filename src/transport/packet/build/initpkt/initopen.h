#ifndef QUIC_INITPKT_INITOPEN_H
#define QUIC_INITPKT_INITOPEN_H

#include "common/bytes/span/span.h"

/* RFC 9001 5.2: open an AEAD-protected Initial packet built by
 * quic_initpkt_build. Re-derives the Initial keys from dcid, removes header
 * protection, and AEAD-opens the payload in place. On success *crypto views
 * the recovered frame bytes within pkt. Returns 1 on success, 0 on
 * authentication failure or short input. */
int quic_initpkt_open(quic_span dcid, quic_mspan pkt, quic_span *crypto);

#endif
