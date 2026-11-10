#include "crypto/pki/cert/p256cert/p256cert.h"

#include "crypto/asymmetric/ecc/ecdsasig/sig_value.h"
#include "crypto/asymmetric/ecc/p256sign/sign.h"
#include "crypto/pki/cert/p256cert/enc.h"
#include "crypto/pki/cert/p256cert/tbs.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/symmetric/hash/hash/sha256.h"

/* RFC 5280 4.1.1.3. SHA-256 the TBS, ECDSA-sign it and write signatureValue
 * BIT STRING (0x00 unused-bits || ECDSA-Sig-Value DER) into vo.
 * p256sign_sign cannot fail and the at most 72-octet ECDSA-Sig-Value always
 * fits bits, so only the caller's vo bounds the result. */
static void pc_sigval(const u8 priv[32], wired_span tbs, wired_obuf* vo) {
  u8  hash[32], r[32], s[32], bits[1 + 80];
  usz n   = 0;
  bits[0] = 0x00;
  wired_sha256(tbs.p, tbs.n, hash);
  p256sign_sign(priv, hash, r, s);
  ecdsasig_encode(r, s, bits + 1, sizeof(bits) - 1, &n);
  selfcert_der_tlv(DER_BIT_STRING, wired_span_of(bits, 1 + n), vo);
}

/* RFC 5280 4.1. Certificate SEQUENCE{ tbs, signatureAlgorithm, sigValue }. */
static int pc_assemble(wired_span tbs, wired_span sv, wired_obuf* out) {
  u8           alg[16], body[640];
  wired_obuf   ao = obuf_of(alg, sizeof(alg));
  p256cert_enc e  = {body, sizeof(body), 0, 1};
  p256cert_put_pre(&e, tbs);
  p256cert_put_pre(&e, wired_span_of(alg, p256cert_sigalg(&ao)));
  p256cert_put_pre(&e, sv);
  out->len = p256cert_wrap(&e, DER_SEQUENCE, out);
  return out->len != 0;
}

/* Every tbs field is fixed-size (at most a 4-octet SAN iPAddress varies),
 * well under tbs[512], so p256cert_tbs cannot fail here; only out bounds
 * the result. */
int p256cert_build(const p256cert_key* k, wired_obuf* out) {
  u8         tbs[512], sv[96];
  wired_obuf to = obuf_of(tbs, sizeof(tbs));
  wired_obuf vo = obuf_of(sv, sizeof(sv));
  p256cert_tbs(k->x, k->y, k->san_ipv4, k->now_secs, &to);
  pc_sigval(k->priv, wired_span_of(tbs, to.len), &vo);
  return pc_assemble(
      wired_span_of(tbs, to.len), wired_span_of(sv, vo.len), out);
}
