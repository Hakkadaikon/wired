#ifndef TLS_BINDER_H
#define TLS_BINDER_H

#include "common/bytes/span/span.h"
#include "crypto/kdf/hkdf/hkdf.h"

/* RFC 8446 4.2.11.2: the PSK binder for resumption PSKs.
 *
 *   early_secret = HKDF-Extract(0, PSK)
 *   binder_key   = Derive-Secret(early_secret, "res binder", "")
 *   finished_key = HKDF-Expand-Label(binder_key, "finished", "", Hash.length)
 *   binder       = HMAC(finished_key, Transcript-Hash(Truncate(ClientHello1)))
 *
 * Only resumption PSKs ("res binder") are in scope: this SDK has no
 * external/out-of-band PSK source (nothing under src/tls/ ever offers one),
 * so the "ext binder" label is not implemented. */

/* binder_key = Derive-Secret(HKDF-Extract(0, psk), "res binder", ""). */
void tls_binder_key(const u8* psk, u8* out);

/* Compute the PskBinderEntry for `psk` over `truncated_ch` -- the
 * ClientHello bytes up to and including the pre_shared_key identities list,
 * EXCLUDING the binders list itself (RFC 8446 4.2.11.2). The caller is
 * responsible for slicing the ClientHello correctly. SHA-256 (32 bytes). */
void tls_binder_compute(const u8* psk, wired_span truncated_ch, u8* out);

/* Verify a presented binder against one recomputed from psk/truncated_ch, in
 * constant time. Returns 1 on a match, 0 otherwise (reject: abort the
 * handshake). received must be 32 bytes (SHA-256). */
int tls_binder_verify(
    const u8* psk, wired_span truncated_ch, const u8* received);

/* Same as tls_binder_compute over suite's hash (psk and out Hash.length). */
void tls_binder_compute_suite(
    u16 suite, const u8* psk, wired_span truncated_ch, u8* out);

/* Same as tls_binder_verify over suite's hash. */
int tls_binder_verify_suite(
    u16 suite, const u8* psk, wired_span truncated_ch, const u8* received);

#endif
