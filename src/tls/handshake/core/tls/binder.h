#ifndef QUIC_TLS_BINDER_H
#define QUIC_TLS_BINDER_H

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
void quic_tls_binder_key(const u8 psk[QUIC_HKDF_PRK], u8 out[QUIC_HKDF_PRK]);

/* Compute the PskBinderEntry for `psk` over `truncated_ch` -- the
 * ClientHello bytes up to and including the pre_shared_key identities list,
 * EXCLUDING the binders list itself (RFC 8446 4.2.11.2). The caller is
 * responsible for slicing the ClientHello correctly. */
void quic_tls_binder_compute(
    const u8 psk[QUIC_HKDF_PRK], quic_span truncated_ch, u8 out[QUIC_HKDF_PRK]);

/* Verify a presented binder against one recomputed from psk/truncated_ch, in
 * constant time. Returns 1 on a match, 0 otherwise (reject: abort the
 * handshake). received must be QUIC_HKDF_PRK (32) bytes. */
int quic_tls_binder_verify(
    const u8  psk[QUIC_HKDF_PRK],
    quic_span truncated_ch,
    const u8  received[QUIC_HKDF_PRK]);

#endif
