#ifndef QUIC_INITPKT_INITPKT_H
#define QUIC_INITPKT_INITPKT_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 5.2 / RFC 9000 17.2.2: build one AEAD-protected client Initial
 * packet. The CRYPTO payload (a ClientHello) is carried in a CRYPTO frame,
 * padded to the 1200-byte datagram minimum, and sealed with the client Initial
 * keys derived from dcid. Writes the protected packet into out (cap bytes) and
 * its length to *out_len. Returns 1 on success, 0 on overflow. */
int quic_initpkt_build(const u8 *dcid, u8 dcid_len,
                       const u8 *scid, u8 scid_len,
                       const u8 *crypto_payload, usz payload_len, u64 pn,
                       u8 *out, usz cap, usz *out_len);

#endif
