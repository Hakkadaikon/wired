#include "crypto/pki/cert/p256cert/p256cert.h"

#include "common/bytes/util/bytes.h"
#include "crypto/asymmetric/ecc/ecdsasig/sig_value.h"
#include "crypto/asymmetric/ecc/p256sign/sign.h"
#include "crypto/pki/cert/p256cert/enc.h"
#include "crypto/pki/cert/p256cert/tbs.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/symmetric/hash/hash/sha256.h"

/* RFC 5280 4.1.1.3. signatureValue BIT STRING (0x00 unused-bits || sig DER).
 * sig is the ECDSA-Sig-Value DER of (r, s). Writes the whole TLV. 0 on fail. */
static usz pc_build_sigval(wired_span sig, wired_obuf* out) {
  u8  bits[80];
  usz off = 1;
  bits[0] = 0x00;
  if (!bytes_put(
          wired_mspan_of(bits, sizeof(bits)), &off,
          wired_span_of(sig.p, sig.n)))
    return 0;
  p256cert_enc e = p256cert_loaded(bits, off);
  return p256cert_wrap(&e, DER_BIT_STRING, out);
}

/* SHA-256 the TBS, ECDSA-sign it, DER-encode (r, s) into sig. 0 on failure. */
static int pc_sign_tbs(const u8 priv[32], wired_span tbs, wired_obuf* sig) {
  u8 hash[32], r[32], s[32];
  wired_sha256(tbs.p, tbs.n, hash);
  if (!p256sign_sign(priv, hash, r, s)) return 0;
  return ecdsasig_encode(r, s, sig->p, sig->cap, &sig->len);
}

int p256cert_build(const p256cert_key* k, wired_obuf* out) {
  u8           tbs[512], alg[16], sig[80], sv[96], body[640];
  wired_obuf   to = obuf_of(tbs, sizeof(tbs));
  wired_obuf   ao = obuf_of(alg, sizeof(alg));
  wired_obuf   go = obuf_of(sig, sizeof(sig));
  wired_obuf   vo = obuf_of(sv, sizeof(sv));
  usz          an = p256cert_sigalg(&ao), svn;
  p256cert_enc e  = {body, sizeof(body), 0, 1};
  if (!p256cert_tbs(k->x, k->y, k->san_ipv4, k->now_secs, &to)) return 0;
  if (!pc_sign_tbs(k->priv, wired_span_of(tbs, to.len), &go)) return 0;
  svn = pc_build_sigval(wired_span_of(sig, go.len), &vo);
  p256cert_put_pre(&e, wired_span_of(tbs, to.len));
  p256cert_put_pre(&e, wired_span_of(alg, an));
  p256cert_put_pre(&e, wired_span_of(sv, svn));
  out->len = p256cert_wrap(&e, DER_SEQUENCE, out);
  return out->len != 0;
}
