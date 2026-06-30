#ifndef QUIC_HSPKT_UNPROTECT_H
#define QUIC_HSPKT_UNPROTECT_H

#include "crypto/symmetric/aead/aes/aes.h"
#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 5.4/5.3 / RFC 9000 A.3: remove header protection over the sample at
 * pn_off+4, recover the FULL packet number from the (1..4-byte) truncated value
 * in the now-cleartext header using largest_pn (the largest packet number seen
 * in this space), then AEAD-open the payload in place with the full pn in the
 * nonce. hdr_len is the header length (through the packet number); bits_mask
 * selects long (0x0f) or short (0x1f) byte0 masking. On success *payload points
 * at the plaintext within pkt and *payload_len is its length. Returns 1 on
 * success, 0 on auth failure or short input. */
int quic_hspkt_unprotect(
    const quic_initial_keys *keys,
    const quic_aes128       *hp,
    u8                      *pkt,
    usz                      len,
    usz                      hdr_len,
    usz                      pn_off,
    u8                       bits_mask,
    u64                      largest_pn,
    const u8               **payload,
    usz                     *payload_len);

#endif
