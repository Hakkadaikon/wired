#ifndef QUIC_CHACHA_AEAD_H
#define QUIC_CHACHA_AEAD_H

#include "crypto/symmetric/aead/chacha/chacha20.h"
#include "crypto/symmetric/aead/chacha/poly1305.h"

/* RFC 8439 2.8 ChaCha20-Poly1305 AEAD. 256-bit key, 96-bit nonce, 16-byte
 * tag. This is QUIC's other packet-protection AEAD (RFC 9001 5.3). */

#define QUIC_CHAPOLY_TAG 16

/* Seal: ct = ChaCha20(pt), tag over aad+ct. Returns ct length (== pt_len). */
usz quic_chapoly_seal(
    const u8  key[QUIC_CHACHA_KEY],
    const u8  nonce[QUIC_CHACHA_NONCE],
    const u8 *aad,
    usz       aad_len,
    const u8 *pt,
    usz       pt_len,
    u8       *ct,
    u8        tag[QUIC_CHAPOLY_TAG]);

/* Open: verify tag then decrypt. Returns 1 on success, 0 on tag mismatch
 * (leaving pt untouched). */
int quic_chapoly_open(
    const u8  key[QUIC_CHACHA_KEY],
    const u8  nonce[QUIC_CHACHA_NONCE],
    const u8 *aad,
    usz       aad_len,
    const u8 *ct,
    usz       ct_len,
    const u8  tag[QUIC_CHAPOLY_TAG],
    u8       *pt);

#endif
