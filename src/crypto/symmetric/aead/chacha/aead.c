#include "crypto/symmetric/aead/chacha/aead.h"

#include "common/bytes/util/ct.h"

/* The MAC input is aad || pad16 || ct || pad16 || le64(aad_len) ||
 * le64(ct_len). We build it into a caller buffer via a small cursor. */

/* Append n bytes of src, then zero-pad up to a 16-byte boundary. */
static usz put_padded(u8 *buf, usz off, const u8 *src, usz n) {
  usz pad = (16 - (n % 16)) % 16;
  for (usz i = 0; i < n; i++) buf[off + i] = src[i];
  for (usz i = 0; i < pad; i++) buf[off + n + i] = 0;
  return off + n + pad;
}

/* Append a little-endian 64-bit length. */
static usz put_le64(u8 *buf, usz off, u64 v) {
  for (usz i = 0; i < 8; i++) buf[off + i] = (u8)(v >> (8 * i));
  return off + 8;
}

/* Derive the one-time Poly1305 key: first 32 bytes of the counter-0 block. */
static void poly_key(const u8 *key, const u8 *nonce, u8 pk[QUIC_POLY1305_KEY]) {
  u8 block[QUIC_CHACHA_BLOCK];
  quic_chacha20_block(key, 0, nonce, block);
  for (usz i = 0; i < QUIC_POLY1305_KEY; i++) pk[i] = block[i];
}

/* Compute the tag over (aad, ct). mac_buf must hold the padded construction. */
static void chapoly_tag(
    const u8 *key,
    const u8 *nonce,
    const u8 *aad,
    usz       aad_len,
    const u8 *ct,
    usz       ct_len,
    u8        tag[16]) {
  u8 pk[QUIC_POLY1305_KEY];
  u8 mac[16 + 1500 + 1500 + 16]; /* MTU-bounded scratch (ponytail: fixed cap) */
  usz n = 0;
  poly_key(key, nonce, pk);
  n = put_padded(mac, n, aad, aad_len);
  n = put_padded(mac, n, ct, ct_len);
  n = put_le64(mac, n, aad_len);
  n = put_le64(mac, n, ct_len);
  quic_poly1305(pk, mac, n, tag);
}

usz quic_chapoly_seal(
    const u8  key[QUIC_CHACHA_KEY],
    const u8  nonce[QUIC_CHACHA_NONCE],
    const u8 *aad,
    usz       aad_len,
    const u8 *pt,
    usz       pt_len,
    u8       *ct,
    u8        tag[QUIC_CHAPOLY_TAG]) {
  quic_chacha20_xor(key, 1, nonce, pt, pt_len, ct);
  chapoly_tag(key, nonce, aad, aad_len, ct, pt_len, tag);
  return pt_len;
}

int quic_chapoly_open(
    const u8  key[QUIC_CHACHA_KEY],
    const u8  nonce[QUIC_CHACHA_NONCE],
    const u8 *aad,
    usz       aad_len,
    const u8 *ct,
    usz       ct_len,
    const u8  tag[QUIC_CHAPOLY_TAG],
    u8       *pt) {
  u8 want[16];
  chapoly_tag(key, nonce, aad, aad_len, ct, ct_len, want);
  if (quic_ct_diff16(want, tag) != 0) return 0; /* reject: leave pt untouched */
  quic_chacha20_xor(key, 1, nonce, ct, ct_len, pt);
  return 1;
}
