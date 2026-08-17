#include "crypto/kdf/hkdf/hkdf.h"

void hkdf_extract(wired_span salt, wired_span ikm, u8 prk[QUIC_HKDF_PRK]) {
  hmac_sha256(salt, ikm, prk);
}

/* Loop-invariant HKDF-Expand inputs: the PRK and the info bytes. */
typedef struct {
  const u8*  prk;
  wired_span info;
} hkdf_xctx;

/* Compute T(i) = HMAC(prk, T(i-1) || info || i) in place: t.p holds T(i-1)
 * of length t.n (0 for T(1)) and receives the 32-byte T(i). */
static void expand_block(const hkdf_xctx* c, wired_mspan t, u8 counter) {
  u8  buf[QUIC_SHA256_DIGEST + 256 + 1];
  usz n = 0;
  for (usz i = 0; i < t.n; i++) buf[n++] = t.p[i];
  for (usz i = 0; i < c->info.n; i++) buf[n++] = c->info.p[i];
  buf[n++] = counter;
  hmac_sha256(wired_span_of(c->prk, QUIC_HKDF_PRK), wired_span_of(buf, n), t.p);
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

int hkdf_expand(const u8 prk[QUIC_HKDF_PRK], wired_span info, wired_mspan okm) {
  u8          t[QUIC_SHA256_DIGEST] = {0};
  hkdf_xctx   c                     = {prk, info};
  wired_mspan tp                    = {t, 0};
  usz         off                   = 0;
  u8          counter               = 1;
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
static void append(u8* info, usz* off, wired_span src) {
  for (usz i = 0; i < src.n; i++) info[*off + i] = src.p[i];
  *off += src.n;
}

/* Build the HkdfLabel struct (RFC 8446 7.1):
 *   uint16 length; opaque label<7..255> = "tls13 "+label; opaque context<>. */
static usz build_label(u8* info, const hkdf_label* l, usz len) {
  static const u8 prefix[6] = {'t', 'l', 's', '1', '3', ' '};
  usz             n         = 0;
  info[n++]                 = (u8)(len >> 8);
  info[n++]                 = (u8)len;
  info[n++]                 = (u8)(6 + l->label_len);
  append(info, &n, wired_span_of(prefix, 6));
  append(info, &n, wired_span_of((const u8*)l->label, l->label_len));
  info[n++] = (u8)l->ctx.n;
  append(info, &n, l->ctx);
  return n;
}

int hkdf_expand_label(
    const u8 prk[QUIC_HKDF_PRK], const hkdf_label* l, wired_mspan okm) {
  u8  info[2 + 1 + 6 + 64 + 1 + 64];
  usz info_len;
  if (l->label_len > 64 || l->ctx.n > 64) return 0;
  info_len = build_label(info, l, okm.n);
  return hkdf_expand(prk, wired_span_of(info, info_len), okm);
}

void hkdf_extract_384(
    wired_span salt, wired_span ikm, u8 prk[QUIC_HKDF_PRK_384]) {
  hmac_sha384(salt, ikm, prk);
}

/* Loop-invariant HKDF-Expand inputs: the PRK and the info bytes. */
typedef struct {
  const u8*  prk;
  wired_span info;
} hkdf_xctx_384;

/* Compute T(i) = HMAC(prk, T(i-1) || info || i) in place: t.p holds T(i-1)
 * of length t.n (0 for T(1)) and receives the 48-byte T(i). */
static void expand_block_384(
    const hkdf_xctx_384* c, wired_mspan t, u8 counter) {
  u8  buf[QUIC_SHA384_DIGEST + 256 + 1];
  usz n = 0;
  for (usz i = 0; i < t.n; i++) buf[n++] = t.p[i];
  for (usz i = 0; i < c->info.n; i++) buf[n++] = c->info.p[i];
  buf[n++] = counter;
  hmac_sha384(
      wired_span_of(c->prk, QUIC_HKDF_PRK_384), wired_span_of(buf, n), t.p);
}

/* Copy up to QUIC_SHA384_DIGEST bytes of t into okm+off, bounded by len. */
static usz emit_384(u8* okm, usz off, usz len, const u8 t[QUIC_SHA384_DIGEST]) {
  usz take = (len - off < QUIC_SHA384_DIGEST) ? len - off : QUIC_SHA384_DIGEST;
  for (usz i = 0; i < take; i++) okm[off + i] = t[i];
  return off + take;
}

/* HKDF-Expand inputs are in range: L <= 255*HashLen and info fits buf. */
static int expand_ok_384(usz info_len, usz len) {
  return len <= (usz)255 * QUIC_SHA384_DIGEST && info_len <= 256;
}

int hkdf_expand_384(
    const u8 prk[QUIC_HKDF_PRK_384], wired_span info, wired_mspan okm) {
  u8            t[QUIC_SHA384_DIGEST] = {0};
  hkdf_xctx_384 c                     = {prk, info};
  wired_mspan   tp                    = {t, 0};
  usz           off                   = 0;
  u8            counter               = 1;
  if (!expand_ok_384(info.n, okm.n)) return 0;
  while (off < okm.n) {
    expand_block_384(&c, tp, counter);
    off  = emit_384(okm.p, off, okm.n, t);
    tp.n = QUIC_SHA384_DIGEST;
    counter++;
  }
  return 1;
}

/* Append src into info at *off, advancing *off. */
static void append_384(u8* info, usz* off, wired_span src) {
  for (usz i = 0; i < src.n; i++) info[*off + i] = src.p[i];
  *off += src.n;
}

/* Build the HkdfLabel struct (RFC 8446 7.1):
 *   uint16 length; opaque label<7..255> = "tls13 "+label; opaque context<>. */
static usz build_label_384(u8* info, const hkdf_label* l, usz len) {
  static const u8 prefix[6] = {'t', 'l', 's', '1', '3', ' '};
  usz             n         = 0;
  info[n++]                 = (u8)(len >> 8);
  info[n++]                 = (u8)len;
  info[n++]                 = (u8)(6 + l->label_len);
  append_384(info, &n, wired_span_of(prefix, 6));
  append_384(info, &n, wired_span_of((const u8*)l->label, l->label_len));
  info[n++] = (u8)l->ctx.n;
  append_384(info, &n, l->ctx);
  return n;
}

int hkdf_expand_label_384(
    const u8 prk[QUIC_HKDF_PRK_384], const hkdf_label* l, wired_mspan okm) {
  u8  info[2 + 1 + 6 + 64 + 1 + 64];
  usz info_len;
  if (l->label_len > 64 || l->ctx.n > 64) return 0;
  info_len = build_label_384(info, l, okm.n);
  return hkdf_expand_384(prk, wired_span_of(info, info_len), okm);
}
