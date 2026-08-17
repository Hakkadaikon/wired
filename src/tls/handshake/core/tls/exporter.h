#ifndef TLS_EXPORTER_H
#define TLS_EXPORTER_H

#include "common/bytes/span/span.h"
#include "crypto/kdf/hkdf/hkdf.h"

/* RFC 8446 7.5: keying material exporters.
 * exporter_master_secret = Derive-Secret(Master Secret, "exp master",
 *   ClientHello...server Finished) (RFC 8446 7.1's key schedule diagram).
 * TLS-Exporter(label, context_value, key_length) =
 *   HKDF-Expand-Label(Derive-Secret(Secret, label, ""),
 *                      "exporter", Hash(context_value), key_length)
 */

/* Derive-Secret(Master Secret, "exp master", transcript) -- the same
 * transcript span (ClientHello..server Finished) keysched_advance_
 * master already hashes for the application traffic secrets. Writes a
 * 32-byte secret. */
void tls_exporter_master_secret(
    const u8  master[HKDF_PRK],
    const u8* transcript,
    usz       transcript_len,
    u8        out[HKDF_PRK]);

/* TLS-Exporter(label, context_value, key_length) (RFC 8446 7.5). Secret
 * must be the exporter_master_secret (tls_exporter_master_secret's
 * output) -- "Implementations MUST use the exporter_master_secret unless
 * explicitly specified by the application." An absent context (context.n
 * == 0 and context.p == 0) and an empty context ({0, non-null}) both hash
 * to the same zero-length input (RFC 8446 7.5: "providing no context
 * computes the same value as providing an empty context").
 * @param secret     exporter_master_secret, HKDF_PRK bytes
 * @param label      exporter label bytes (no "tls13 " prefix; that is
 *                   applied internally by the two HKDF-Expand-Label calls)
 * @param context    context_value to hash into the output
 * @param okm        receives exactly okm.n bytes of exported keying
 *                   material
 * @return 1 on success, 0 if a length does not fit (see
 *   hkdf_expand_label) */
int tls_exporter(
    const u8    secret[HKDF_PRK],
    wired_span  label,
    wired_span  context,
    wired_mspan okm);

#endif
