#include "tls/handshake/core/sdrv/sdrv_impl.h"

/* RFC 8446 4.2 / 6.2: the vector-valued ClientHello extension bodies this
 * server reads must decode -- otherwise decode_error (the structure gates
 * are in sdrv_ch_decode.c, pre_shared_key's in sdrv_ch_psk.c). */

/* RFC 8446 4.2: the shape of a vector-valued extension body -- a w-byte
 * length prefix, entries walked by step, at least min of them. */
typedef struct {
  unsigned      type;
  usz           w;
  sdrv_vec_step step;
  usz           min;
} sdrv_ext_shape;

static usz sdrv_u8_step(const u8* p, usz q, usz n);
static usz sdrv_u16_step(const u8* p, usz q, usz n);
static usz sdrv_ks_step(const u8* p, usz q, usz n);
static int sdrv_ext_shape_ok(
    const u8* ch_msg, usz ch_len, const sdrv_ext_shape* sh);

/* RFC 8446 4.2.3 / 4.2.7 / 4.2.1 / 4.2.9 / 4.2.8: the vector-valued
 * ClientHello extensions this server reads. supported_versions is a 1-byte
 * prefixed list of 2-byte versions; client_shares may be empty (a client
 * asking for an HRR). */
static const sdrv_ext_shape SDRV_EXT_SHAPES[] = {
    {EXT_SUPPORTED_GROUPS, 2, sdrv_u16_step, 1},
    {EXT_SIGNATURE_ALGORITHMS, 2, sdrv_u16_step, 1},
    {SDRV_SIG_ALGS_CERT_EXT_TYPE, 2, sdrv_u16_step, 1},
    {EXT_SUPPORTED_VERSIONS, 1, sdrv_u16_step, 1},
    {TLSEXT_T_PSK_MODES, 1, sdrv_u8_step, 1},
    {EXT_KEY_SHARE, 2, sdrv_ks_step, 0},
};

static usz sdrv_u8_step(const u8* p, usz q, usz n) {
  (void)p;
  return q + 1 <= n ? q + 1 : 0;
}

static usz sdrv_u16_step(const u8* p, usz q, usz n) {
  (void)p;
  return q + 2 <= n ? q + 2 : 0;
}

/* RFC 8446 4.2.8: KeyShareEntry = group(2) key_exchange<1..2^16-1>. */
static usz sdrv_ks_step(const u8* p, usz q, usz n) {
  usz e = sdrv_entry_end(p, q + 2, n, 2);
  return e > q + 4 ? e : 0;
}

/* An absent extension has nothing to check. */
static int sdrv_ext_shape_ok(
    const u8* ch_msg, usz ch_len, const sdrv_ext_shape* sh) {
  wired_span ext;
  if (!sdrv_find_client_ext(ch_msg, ch_len, sh->type, &ext)) {
    return 1;
  }
  return sdrv_vec_ok(
      wired_span_of(ext.p + 4, ext.n - 4), sh->w, sh->step, sh->min);
}

/* RFC 8446 6.2: a vector-valued extension body that does not decode is
 * decode_error. */
int sdrv_ch_require_ext_shapes(sdrv* s, const u8* ch_msg, usz ch_len) {
  for (usz i = 0; i < sizeof SDRV_EXT_SHAPES / sizeof *SDRV_EXT_SHAPES; i++) {
    if (!sdrv_ext_shape_ok(ch_msg, ch_len, &SDRV_EXT_SHAPES[i])) {
      return sdrv_ch_reject(s, 50);
    }
  }
  return 1;
}
