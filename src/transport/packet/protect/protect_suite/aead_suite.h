#ifndef QUIC_PROTECT_SUITE_AEAD_SUITE_H
#define QUIC_PROTECT_SUITE_AEAD_SUITE_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 5.3: per-suite AEAD seal/open for QUIC packet protection. The
 * 12-byte nonce is iv XOR pn (left-padded). AES suites (0x1301) use
 * AES-128-GCM, ChaCha suites (0x1303) use ChaCha20-Poly1305. key is 16
 * bytes for AES, 32 for ChaCha; iv is 12 bytes either way. */

/* Seal pt into out as ciphertext followed by the 16-byte tag. Returns the
 * total written length (pt_len + 16), or 0 on an unknown suite. */
usz quic_aead_suite_seal(u16 suite, const u8 *key, const u8 *iv, u64 pn,
                         const u8 *aad, usz aad_len,
                         const u8 *pt, usz pt_len, u8 *out);

/* Open ct (ct_len ciphertext bytes followed by a 16-byte tag) into pt.
 * Returns pt_len on success, 0 on tag mismatch or unknown suite. */
usz quic_aead_suite_open(u16 suite, const u8 *key, const u8 *iv, u64 pn,
                         const u8 *aad, usz aad_len,
                         const u8 *ct, usz ct_len, u8 *pt);

#endif
