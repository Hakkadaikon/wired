#include "crypto/kdf/hkdf/hkdf.h"

void quic_hkdf_extract(quic_span salt, quic_span ikm, u8 prk[QUIC_HKDF_PRK]) {
  quic_hmac_sha256(salt, ikm, prk);
}

/* Loop-invariant HKDF-Expand inputs: the PRK and the info bytes. */
typedef struct {
  const u8* prk;
  quic_span info;
} quic_hkdf_xctx;

/* Compute T(i) = HMAC(prk, T(i-1) || info || i) in place: t.p holds T(i-1)
 * of length t.n (0 for T(1)) and receives the 32-byte T(i). */
static void expand_block(const quic_hkdf_xctx* c, quic_mspan t, u8 counter) {
  u8  buf[QUIC_SHA256_DIGEST + 256 + 1];
  usz n = 0;
  for (usz i = 0; i < t.n; i++) buf[n++] = t.p[i];
  for (usz i = 0; i < c->info.n; i++) buf[n++] = c->info.p[i];
  buf[n++] = counter;
  quic_hmac_sha256(
      quic_span_of(c->prk, QUIC_HKDF_PRK), quic_span_of(buf, n), t.p);
}

/* Copy up to QUIC_SHA256_DIGEST bytes of t into okm+off, bounded by len. */
static usz emit(u8* okm, usz off, usz len, const u8 t[QUIC_SHA256_DIGEST]) {
  usz take = (len - off < QUIC_SHA256_DIGEST) ? len - off : QUIC_SHA256_DIGEST;
  for (usz i = 0; i < take; i++) okm[off + i] = t[i];
  return off + take;
}

/* HKDF-Expand inputs are in range: L <= 255*HashLen and info fits buf. */
static int expand_ok(usz info_len, usz len) {
  return len <= (usz)255 * QUIC_SHA256_DIGEST && info_len <= 256;
}

int quic_hkdf_expand(
    const u8 prk[QUIC_HKDF_PRK], quic_span info, quic_mspan okm) {
  u8             t[QUIC_SHA256_DIGEST] = {0};
  quic_hkdf_xctx c                     = {prk, info};
  quic_mspan     tp                    = {t, 0};
  usz            off                   = 0;
  u8             counter               = 1;
  if (!expand_ok(info.n, okm.n)) return 0;
  while (off < okm.n) {
    expand_block(&c, tp, counter);
    off  = emit(okm.p, off, okm.n, t);
    tp.n = QUIC_SHA256_DIGEST;
    counter++;
  }
  return 1;
}

/* Append src into info at *off, advancing *off. */
static void append(u8* info, usz* off, quic_span src) {
  for (usz i = 0; i < src.n; i++) info[*off + i] = src.p[i];
  *off += src.n;
}

/* Build the HkdfLabel struct (RFC 8446 7.1):
 *   uint16 length; opaque label<7..255> = "tls13 "+label; opaque context<>. */
static usz build_label(u8* info, const quic_hkdf_label* l, usz len) {
  static const u8 prefix[6] = {'t', 'l', 's', '1', '3', ' '};
  usz             n         = 0;
  info[n++]                 = (u8)(len >> 8);
  info[n++]                 = (u8)len;
  info[n++]                 = (u8)(6 + l->label_len);
  append(info, &n, quic_span_of(prefix, 6));
  append(info, &n, quic_span_of((const u8*)l->label, l->label_len));
  info[n++] = (u8)l->ctx.n;
  append(info, &n, l->ctx);
  return n;
}

int quic_hkdf_expand_label(
    const u8 prk[QUIC_HKDF_PRK], const quic_hkdf_label* l, quic_mspan okm) {
  u8  info[2 + 1 + 6 + 64 + 1 + 64];
  usz info_len;
  if (l->label_len > 64 || l->ctx.n > 64) return 0;
  info_len = build_label(info, l, okm.n);
  return quic_hkdf_expand(prk, quic_span_of(info, info_len), okm);
}
