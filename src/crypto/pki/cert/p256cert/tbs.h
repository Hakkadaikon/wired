#ifndef P256CERT_TBS_H
#define P256CERT_TBS_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1. Build a v3 TBSCertificate (self-issued CN=localhost,
 * ecdsa-with-SHA256 signature AlgID, secp256r1 SPKI) from the affine public
 * key into out, setting out->len. san_ipv4/now_secs: see p256cert_key's
 * doc (0 to omit/use the fixed window). Returns 1 ok, 0 on failure. */
int p256cert_tbs(
    const u8    x[32],
    const u8    y[32],
    const u8*   san_ipv4,
    u64         now_secs,
    wired_obuf* out);

/* RFC 5480 2.1.1. signatureAlgorithm SEQUENCE { ecdsa-with-SHA256 } (no
 * params). Writes the whole TLV into out. Returns its length, 0 on failure. */
usz p256cert_sigalg(wired_obuf* out);

#endif
