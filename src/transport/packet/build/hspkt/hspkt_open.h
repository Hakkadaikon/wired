#ifndef HSPKT_HSPKT_OPEN_H
#define HSPKT_HSPKT_OPEN_H

#include "transport/packet/protect/protect/protect.h"

/* RFC 9001 5: open a Handshake packet built by hspkt_build. Removes
 * header protection, recovers the full packet number from its truncated
 * wire form against largest_pn (the largest packet number received so far
 * in this space, 0 before any -- RFC 9000 A.3), and AEAD-opens the payload
 * in place with k. On success *payload views the plaintext within pkt.
 * Returns 1 on success, 0 on authentication failure or short input
 * (AES-128-GCM; equivalent to hspkt_open_suite with suite =
 * TLS_AES_128_GCM_SHA256). */
int hspkt_open(
    const protect_keys* k,
    wired_mspan         pkt,
    u64                 largest_pn,
    wired_span*         payload);

/* Same as hspkt_open, but opens under the given negotiated TLS 1.3
 * cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int hspkt_open_suite(
    u16                 suite,
    const protect_keys* k,
    wired_mspan         pkt,
    u64                 largest_pn,
    wired_span*         payload);

#endif
