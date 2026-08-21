#ifndef HSPKT_HSPKT_BUILD_H
#define HSPKT_HSPKT_BUILD_H

#include "transport/packet/protect/protect/protect.h"

/* RFC 9000 17.2.4 / RFC 9001 5: build one AEAD-protected Handshake packet.
 * The Handshake long header carries no token (unlike Initial). */

/** One Handshake packet to build: CIDs, packet number, and the payload
 * (typically a CRYPTO frame). version selects the long header's Version
 * field and its Handshake type bits (RFC 9369 3.2 for v2); 0 (every
 * pre-existing positional initializer) means QUIC v1. */
typedef struct {
  wired_span dcid;
  wired_span scid;
  u64        pn;
  wired_span payload;
  u32        version;
} hspkt_desc;

/* Seal with the Handshake keys k and write the protected packet into out;
 * length to out->len. Returns 1 on success, 0 on overflow (AES-128-GCM;
 * equivalent to hspkt_build_suite with suite =
 * TLS_AES_128_GCM_SHA256). */
int hspkt_build(const protect_keys* k, const hspkt_desc* d, wired_obuf* out);

/* Same as hspkt_build, but seals under the given negotiated TLS 1.3
 * cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int hspkt_build_suite(
    u16 suite, const protect_keys* k, const hspkt_desc* d, wired_obuf* out);

#endif
