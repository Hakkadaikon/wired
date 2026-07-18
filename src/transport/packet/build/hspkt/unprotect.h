#ifndef QUIC_HSPKT_UNPROTECT_H
#define QUIC_HSPKT_UNPROTECT_H

#include "transport/packet/protect/protect/protect.h"

/* RFC 9001 5.4/5.3 / RFC 9000 A.3: remove header protection over the sample at
 * pn_off+4, recover the FULL packet number from the (1..4-byte) truncated value
 * in the now-cleartext header using largest_pn (the largest packet number seen
 * in this space), then AEAD-open the payload in place with the full pn in the
 * nonce. */

/* One protected packet to open in place. hdr_len is the header length
 * (through the packet number); bits_mask selects long (0x0f) or short (0x1f)
 * byte0 masking. */
typedef struct {
  quic_mspan pkt;
  usz        hdr_len;
  usz        pn_off;
  u8         bits_mask;
  u64        largest_pn;
} quic_hspkt_unprotect_desc;

/* On success *payload views the plaintext within pkt. Returns 1 on success,
 * 0 on auth failure or short input (AES-128-GCM; equivalent to
 * quic_hspkt_unprotect_suite with suite = QUIC_TLS_AES_128_GCM_SHA256). */
int quic_hspkt_unprotect(
    const quic_protect_keys*         k,
    const quic_hspkt_unprotect_desc* d,
    quic_span*                       payload);

/* Same as quic_hspkt_unprotect, but opens under the given negotiated TLS 1.3
 * cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int quic_hspkt_unprotect_suite(
    u16                              suite,
    const quic_protect_keys*         k,
    const quic_hspkt_unprotect_desc* d,
    quic_span*                       payload);

#endif
