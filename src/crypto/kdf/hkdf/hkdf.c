#include "crypto/kdf/hkdf/hkdf.h"

void quic_hkdf_extract(
    const u8 *salt,
    usz       salt_len,
    const u8 *ikm,
    usz       ikm_len,
    u8        prk[QUIC_HKDF_PRK]) {
  quic_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

/* Compute T(i) = HMAC(prk, T(i-1) || info || i) into t. prev is T(i-1)
 * (prev_len = 0 for T(1)). */
static void expand_block(
    const u8 *prk,
    const u8 *prev,
    usz       prev_len,
    const u8 *info,
    usz       info_len,
    u8        counter,
    u8        t[QUIC_SHA256_DIGEST]) {
  u8  buf[QUIC_SHA256_DIGEST + 256 + 1];
  usz n = 0;
  for (usz i = 0; i < prev_len; i++) buf[n++] = prev[i];
  for (usz i = 0; i < info_len; i++) buf[n++] = info[i];
  buf[n++] = counter;
  quic_hmac_sha256(prk, QUIC_HKDF_PRK, buf, n, t);
}

/* Copy up to QUIC_SHA256_DIGEST bytes of t into okm+off, bounded by len. */
static usz emit(u8 *okm, usz off, usz len, const u8 t[QUIC_SHA256_DIGEST]) {
  usz take = (len - off < QUIC_SHA256_DIGEST) ? len - off : QUIC_SHA256_DIGEST;
  for (usz i = 0; i < take; i++) okm[off + i] = t[i];
  return off + take;
}

/* HKDF-Expand inputs are in range: L <= 255*HashLen and info fits buf. */
static int expand_ok(usz info_len, usz len) {
  return len <= (usz)255 * QUIC_SHA256_DIGEST && info_len <= 256;
}

int quic_hkdf_expand(
    const u8  prk[QUIC_HKDF_PRK],
    const u8 *info,
    usz       info_len,
    u8       *okm,
    usz       len) {
  u8  t[QUIC_SHA256_DIGEST];
  usz off = 0, prev_len = 0;
  u8  counter = 1;
  if (!expand_ok(info_len, len)) return 0;
  while (off < len) {
    expand_block(prk, t, prev_len, info, info_len, counter, t);
    off      = emit(okm, off, len, t);
    prev_len = QUIC_SHA256_DIGEST;
    counter++;
  }
  return 1;
}

/* Append n bytes of src into info at *off, advancing *off. */
static void append(u8 *info, usz *off, const u8 *src, usz n) {
  for (usz i = 0; i < n; i++) info[*off + i] = src[i];
  *off += n;
}

/* Build the HkdfLabel struct (RFC 8446 7.1):
 *   uint16 length; opaque label<7..255> = "tls13 "+label; opaque context<>. */
static usz build_label(
    u8         *info,
    const char *label,
    usz         label_len,
    const u8   *ctx,
    usz         ctx_len,
    usz         len) {
  static const u8 prefix[6] = {'t', 'l', 's', '1', '3', ' '};
  usz             n         = 0;
  info[n++]                 = (u8)(len >> 8);
  info[n++]                 = (u8)len;
  info[n++]                 = (u8)(6 + label_len);
  append(info, &n, prefix, 6);
  append(info, &n, (const u8 *)label, label_len);
  info[n++] = (u8)ctx_len;
  append(info, &n, ctx, ctx_len);
  return n;
}

int quic_hkdf_expand_label(
    const u8    prk[QUIC_HKDF_PRK],
    const char *label,
    usz         label_len,
    const u8   *ctx,
    usz         ctx_len,
    u8         *okm,
    usz         len) {
  u8  info[2 + 1 + 6 + 64 + 1 + 64];
  usz info_len;
  if (label_len > 64 || ctx_len > 64) return 0;
  info_len = build_label(info, label, label_len, ctx, ctx_len, len);
  return quic_hkdf_expand(prk, info, info_len, okm, len);
}
