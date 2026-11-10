#include "crypto/pki/cert/selfcert/selfcert.h"

#include "common/bytes/util/bytes.h"
#include "crypto/asymmetric/ecc/ed25519/ed25519.h"
#include "crypto/pki/cert/selfcert/derenc.h"
#include "crypto/pki/cert/selfcert/tbs.h"
#include "crypto/pki/encoding/asn1/der.h"

/* RFC 5280 4.1.1.2 / RFC 8410 3. signatureAlgorithm SEQUENCE { id-Ed25519 }
 * (no parameters). */
static const u8 selfcert_sigalg[] = {0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70};
/* RFC 5280 4.1.1.3. signatureValue BIT STRING header: 65 octets, the first
 * the 0 unused-bits count, then the 64-byte Ed25519 signature. */
static const u8 selfcert_sighead[] = {0x03, 0x41, 0x00};

/* The tbs, then signatureAlgorithm and signatureValue, into body. */
static usz selfcert_body(wired_span tbs, const u8 sig[64], u8 body[256]) {
  wired_mspan m   = wired_mspan_of(body, 256);
  usz         off = 0;
  bytes_put(m, &off, tbs);
  bytes_put(m, &off, wired_span_of(selfcert_sigalg, sizeof(selfcert_sigalg)));
  bytes_put(m, &off, wired_span_of(selfcert_sighead, sizeof(selfcert_sighead)));
  bytes_put(m, &off, wired_span_of(sig, 64));
  return off;
}

/* ed25519_keypair/ed25519_sign cannot fail and the fixed-size tbs fits
 * tbs[160], so only the caller's cert_out can be too small. */
int selfcert_build(const u8 seed[32], wired_obuf* cert_out) {
  u8         pub[32], sig[64], tbs[160], body[256];
  wired_obuf to = obuf_of(tbs, sizeof(tbs));
  usz        n;
  ed25519_keypair(seed, pub);
  selfcert_tbs(pub, &to);
  ed25519_sign(seed, tbs, to.len, sig);
  n = selfcert_body(wired_span_of(tbs, to.len), sig, body);
  return selfcert_der_tlv(DER_SEQUENCE, wired_span_of(body, n), cert_out);
}
