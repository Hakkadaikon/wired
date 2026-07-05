#ifndef QUIC_INITPKT_INITPKT_H
#define QUIC_INITPKT_INITPKT_H

#include "common/bytes/span/span.h"

/* RFC 9001 5.2 / RFC 9000 17.2.2: build one AEAD-protected client Initial
 * packet. The CRYPTO payload (a ClientHello) is carried in a CRYPTO frame,
 * padded to the 1200-byte datagram minimum, and sealed with the client Initial
 * keys derived from dcid. */
typedef struct {
  quic_span dcid;
  quic_span scid;
  quic_span crypto; /* the ClientHello bytes (or a chunk of them) */
  u64       pn;
  u64       crypto_off; /* CRYPTO stream offset of crypto's first byte
                           (RFC 9000 19.6): 0 for an unsplit ClientHello */
} quic_initpkt_desc;

/* Writes the protected packet into out (length to out->len). Returns 1 on
 * success, 0 on overflow. */
int quic_initpkt_build(const quic_initpkt_desc* d, quic_obuf* out);

#endif
