#ifndef QUIC_GCM_GCM_H
#define QUIC_GCM_GCM_H

#include "crypto/symmetric/aead/aes/aes.h"

/* AES-128-GCM AEAD (NIST SP 800-38D). 96-bit nonce, 128-bit tag. This is
 * the AEAD QUIC uses for AES-based packet protection (RFC 9001 5.3). */

#define QUIC_GCM_NONCE 12
#define QUIC_GCM_TAG 16

/* Seal: encrypt plaintext and append a 16-byte tag.
 * ct must have room for pt_len bytes; tag is written separately.
 * Returns the ciphertext length (== pt_len). */
usz quic_gcm_seal(
    const quic_aes128 *a,
    const u8           nonce[QUIC_GCM_NONCE],
    const u8          *aad,
    usz                aad_len,
    const u8          *pt,
    usz                pt_len,
    u8                *ct,
    u8                 tag[QUIC_GCM_TAG]);

/* Open: verify the tag and decrypt. On tag mismatch, returns 0 and does NOT
 * write plaintext. On success, writes pt_len bytes to pt and returns 1. */
int quic_gcm_open(
    const quic_aes128 *a,
    const u8           nonce[QUIC_GCM_NONCE],
    const u8          *aad,
    usz                aad_len,
    const u8          *ct,
    usz                ct_len,
    const u8           tag[QUIC_GCM_TAG],
    u8                *pt);

#endif
