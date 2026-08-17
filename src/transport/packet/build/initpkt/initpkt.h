#ifndef INITPKT_INITPKT_H
#define INITPKT_INITPKT_H

#include "common/bytes/span/span.h"

/** RFC 9001 5.2 / RFC 9000 17.2.2: build one AEAD-protected client Initial
 * packet. The CRYPTO payload (a ClientHello) is carried in a CRYPTO frame,
 * padded to the 1200-byte datagram minimum, and sealed with the client
 * Initial keys derived from dcid. */
typedef struct {
  wired_span dcid;
  wired_span scid;
  wired_span crypto; /* the ClientHello bytes (or a chunk of them) */
  u64        pn;
  u64        crypto_off; /* CRYPTO stream offset of crypto's first byte
                            (RFC 9000 19.6): 0 for an unsplit ClientHello */
} initpkt_desc;

/* Writes the protected packet into out (length to out->len). Returns 1 on
 * success, 0 on overflow. Equivalent to initpkt_build_ver(d,
 * VERSION_1, out). */
int initpkt_build(const initpkt_desc* d, wired_obuf* out);

/* Same as initpkt_build, but the Initial keys, the header's Version
 * field, and byte0's type bits all follow `version` (RFC 9369 3.2/3.3.1)
 * instead of assuming QUIC v1. Returns 0 on overflow or an unencodable
 * version. */
int initpkt_build_ver(u32 version, const initpkt_desc* d, wired_obuf* out);

#endif
