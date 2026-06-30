#ifndef QUIC_HSPKT_HSPKT_OPEN_H
#define QUIC_HSPKT_HSPKT_OPEN_H

#include "crypto/symmetric/aead/aes/aes.h"
#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 5: open a Handshake packet built by quic_hspkt_build. Removes
 * header protection, recovers the packet number from the header, and AEAD-opens
 * the payload in place with hs_keys. On success *payload points at the
 * plaintext within pkt and *payload_len holds its length. Returns 1 on success,
 * 0 on authentication failure or short input. */
int quic_hspkt_open(
    const quic_initial_keys *hs_keys,
    const quic_aes128       *hp,
    u8                      *pkt,
    usz                      len,
    u8                       dcid_len,
    const u8               **payload,
    usz                     *payload_len);

#endif
