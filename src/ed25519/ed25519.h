#ifndef QUIC_ED25519_ED25519_H
#define QUIC_ED25519_ED25519_H

#include "sys/syscall.h"

/* RFC 8032 Section 5.1: Ed25519 signing and verification (PureEdDSA). */

#define QUIC_ED25519_SEED   32
#define QUIC_ED25519_PUBKEY 32
#define QUIC_ED25519_SIG    64

/* Verify sig (R||S, 64 bytes) over msg under pubkey (32 bytes).
 * Returns 1 if the signature is valid, 0 otherwise. */
int quic_ed25519_verify(const u8 sig[QUIC_ED25519_SIG],
                        const u8 *msg, usz msg_len,
                        const u8 pubkey[QUIC_ED25519_PUBKEY]);

/* Derive the 32-byte public key from a 32-byte seed (RFC 8032 5.1.5). */
int quic_ed25519_keypair(const u8 seed[QUIC_ED25519_SEED],
                         u8 public_key[QUIC_ED25519_PUBKEY]);

/* Sign msg under seed, writing R||S (64 bytes) to sig (RFC 8032 5.1.6). */
int quic_ed25519_sign(const u8 seed[QUIC_ED25519_SEED],
                      const u8 *msg, usz msg_len,
                      u8 sig[QUIC_ED25519_SIG]);

#endif
