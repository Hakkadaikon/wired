#include "tls/ext/tlsext/preshared.h"

#include "common/bytes/util/be.h"

#define QUIC_TLSEXT_T_PRE_SHARED_KEY 0x0029

static void psk_copy(u8* dst, const u8* src, usz n) {
  for (usz i = 0; i < n; i++) dst[i] = src[i];
}

/* RFC 8446 4.2.11: ext_data = identities_len(2) + (id_len(2)+id+age(4)) +
 * binders_len(2) + (binder_len(1)+binder). */
static usz psk_total(usz id_len, usz binder_len) {
  return 4 + 2 + (2 + id_len + 4) + 2 + (1 + binder_len);
}

int quic_tlsext_pre_shared_key(const quic_tlsext_psk_in* in, quic_obuf* out) {
  usz id_len     = in->identity.n;
  usz binder_len = in->binder.n;
  usz total      = psk_total(id_len, binder_len);
  u8* p          = out->p;
  if (out->cap < total) return 0;
  quic_put_be16(p, QUIC_TLSEXT_T_PRE_SHARED_KEY);
  quic_put_be16(p + 2, (u16)(total - 4));
  quic_put_be16(p + 4, (u16)(2 + id_len + 4));
  quic_put_be16(p + 6, (u16)id_len);
  psk_copy(p + 8, in->identity.p, id_len);
  quic_put_be32(p + 8 + id_len, in->ticket_age);
  quic_put_be16(p + 12 + id_len, (u16)(1 + binder_len));
  p[14 + id_len] = (u8)binder_len;
  psk_copy(p + 15 + id_len, in->binder.p, binder_len);
  out->len = total;
  return 1;
}

/* The 4-byte header names pre_shared_key with the full body readable. */
static int psk_header_ok(const u8* out, usz n) {
  usz dlen = (usz)out[2] << 8 | out[3];
  return n >= 4 &&
         ((u16)out[0] << 8 | out[1]) == QUIC_TLSEXT_T_PRE_SHARED_KEY &&
         4 + dlen <= n;
}

/* CID lengths (identity, binder) of a single-entry offer. */
typedef struct {
  usz id_len;
  usz binder_len;
} psk_lens;

/* The single identity entry and single binder entry exactly fill the body. */
static int psk_shape_ok(const u8* out, usz n, psk_lens l) {
  usz dlen = (usz)out[2] << 8 | out[3];
  return n >= psk_total(l.id_len, l.binder_len) &&
         dlen == psk_total(l.id_len, l.binder_len) - 4;
}

/* Header valid and the identity entry leaves the binder length byte readable.
 */
static int psk_prefix_ok(const u8* out, usz n, usz id_len) {
  return psk_header_ok(out, n) && n >= 15 + id_len;
}

/* The full single-entry offer is well formed: prefix readable then both
 * single-entry lists exactly fill the body. */
static int psk_offer_ok(const u8* out, usz n, usz id_len) {
  psk_lens l = {id_len, out[14 + id_len]};
  return psk_prefix_ok(out, n, id_len) && psk_shape_ok(out, n, l);
}

int quic_tlsext_pre_shared_key_parse(
    const u8* out, usz n, quic_tlsext_psk_offer* off) {
  usz id_len = (n >= 8) ? ((usz)out[6] << 8 | out[7]) : 0;
  if (!psk_offer_ok(out, n, id_len)) return 0;
  off->binder_len = out[14 + id_len];
  off->identity   = out + 8;
  off->id_len     = id_len;
  off->ticket_age = (u32)out[8 + id_len] << 24 | (u32)out[9 + id_len] << 16 |
                    (u32)out[10 + id_len] << 8 | out[11 + id_len];
  off->binder     = out + 15 + id_len;
  return 1;
}
