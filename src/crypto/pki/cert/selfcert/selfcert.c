#include "crypto/pki/cert/selfcert/selfcert.h"

#include "common/bytes/util/bytes.h"
#include "crypto/asymmetric/ecc/ed25519/ed25519.h"
#include "crypto/pki/cert/selfcert/derenc.h"
#include "crypto/pki/cert/selfcert/tbs.h"
#include "crypto/pki/encoding/asn1/der.h"

/* RFC 8410 3. id-Ed25519 OID 1.3.101.112. */
static const u8 oid_ed25519_sig[] = {0x2b, 0x65, 0x70};

/* RFC 5280 4.1.1.2. signatureAlgorithm SEQUENCE { id-Ed25519 } (no params). */
static usz build_sigalg(quic_obuf *out) {
  u8        oid[16];
  quic_obuf o = quic_obuf_of(oid, sizeof(oid));
  if (!quic_selfcert_der_tlv(
          QUIC_DER_OID, quic_span_of(oid_ed25519_sig, sizeof(oid_ed25519_sig)),
          &o))
    return 0;
  if (!quic_selfcert_der_tlv(QUIC_DER_SEQUENCE, quic_span_of(oid, o.len), out))
    return 0;
  return out->len;
}

/* RFC 5280 4.1.1.3. signatureValue BIT STRING (0x00 unused bits || sig). */
static usz build_sigval(const u8 sig[64], quic_obuf *out) {
  u8  bits[65];
  usz off = 1;
  bits[0] = 0x00;
  quic_put_bytes(quic_mspan_of(bits, sizeof(bits)), &off, quic_span_of(sig, 64));
  if (!quic_selfcert_der_tlv(QUIC_DER_BIT_STRING, quic_span_of(bits, off), out))
    return 0;
  return out->len;
}

/* Concatenate the parts and wrap in the Certificate SEQUENCE. */
static int assemble(const quic_span *parts, usz cnt, quic_obuf *out) {
  u8  body[768];
  usz off = 0;
  int ok  = 1;
  for (usz i = 0; i < cnt; i++)
    ok &= quic_put_bytes(quic_mspan_of(body, sizeof(body)), &off, quic_span_of(parts[i].p, parts[i].n));
  return ok &&
         quic_selfcert_der_tlv(QUIC_DER_SEQUENCE, quic_span_of(body, off), out);
}

/* Derive the public key and sign the freshly built TBS. 0 on any failure. */
static int sign_tbs(const u8 seed[32], quic_obuf *tbs, u8 sig[64]) {
  u8 pub[32];
  if (!quic_ed25519_keypair(seed, pub)) return 0;
  if (!quic_selfcert_tbs(pub, tbs)) return 0;
  return quic_ed25519_sign(seed, tbs->p, tbs->len, sig);
}

/* True if all three lengths are non-zero (every element encoded). */
static int parts_ok(const quic_span *p) { return p[0].n && p[1].n && p[2].n; }

int quic_selfcert_build(const u8 seed[32], quic_obuf *cert_out) {
  u8        sig[64], tbs[512], alg[16], sv[80];
  quic_obuf to = quic_obuf_of(tbs, sizeof(tbs));
  quic_obuf ao = quic_obuf_of(alg, sizeof(alg));
  quic_obuf vo = quic_obuf_of(sv, sizeof(sv));
  usz       an = build_sigalg(&ao);
  if (!sign_tbs(seed, &to, sig)) return 0;
  usz       sn      = build_sigval(sig, &vo);
  quic_span parts[] = {{tbs, to.len}, {alg, an}, {sv, sn}};
  if (!parts_ok(parts)) return 0;
  return assemble(parts, 3, cert_out);
}
