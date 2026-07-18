#ifndef QUIC_HSPKT_HSPKT_BUILD_H
#define QUIC_HSPKT_HSPKT_BUILD_H

#include "transport/packet/protect/protect/protect.h"

/* RFC 9000 17.2.4 / RFC 9001 5: build one AEAD-protected Handshake packet.
 * The Handshake long header carries no token (unlike Initial). */

/* One Handshake packet to build: CIDs, packet number, and the payload
 * (typically a CRYPTO frame). */
typedef struct {
  quic_span dcid;
  quic_span scid;
  u64       pn;
  quic_span payload;
} quic_hspkt_desc;

/* Seal with the Handshake keys k and write the protected packet into out;
 * length to out->len. Returns 1 on success, 0 on overflow (AES-128-GCM;
 * equivalent to quic_hspkt_build_suite with suite =
 * QUIC_TLS_AES_128_GCM_SHA256). */
int quic_hspkt_build(
    const quic_protect_keys* k, const quic_hspkt_desc* d, quic_obuf* out);

/* Same as quic_hspkt_build, but seals under the given negotiated TLS 1.3
 * cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int quic_hspkt_build_suite(
    u16                      suite,
    const quic_protect_keys* k,
    const quic_hspkt_desc*   d,
    quic_obuf*               out);

#endif
