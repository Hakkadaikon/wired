#ifndef QUIC_HSPKT_HSPKT_BUILD_H
#define QUIC_HSPKT_HSPKT_BUILD_H

#include "tls/handshake/core/tls/initial.h"
#include "crypto/symmetric/aead/aes/aes.h"

/* RFC 9000 17.2.4 / RFC 9001 5: build one AEAD-protected Handshake packet.
 * The Handshake long header carries no token (unlike Initial). The payload
 * (typically a CRYPTO frame) is sealed with the Handshake keys hs_keys and
 * header-protected with hp. Writes the protected packet into out (cap bytes)
 * and its length to *out_len. Returns 1 on success, 0 on overflow. */
int quic_hspkt_build(const quic_initial_keys *hs_keys, const quic_aes128 *hp,
                     const u8 *dcid, u8 dcid_len,
                     const u8 *scid, u8 scid_len, u64 pn,
                     const u8 *payload, usz payload_len,
                     u8 *out, usz cap, usz *out_len);

#endif
