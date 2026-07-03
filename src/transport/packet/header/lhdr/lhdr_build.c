#include "transport/packet/header/lhdr/lhdr_build.h"

#include "common/bytes/varint/varint.h"
#include "transport/packet/header/packet/header.h"
#include "transport/packet/header/packet/inittoken.h"
#include "transport/packet/header/packet/pnum.h"

/* RFC 9000 17.2: low two bits of byte0 hold pn_len-1 (1->0, 2->1, 4->3). */
u8 quic_lhdr_byte0_pnlen(u8 byte0, u8 pn_len) {
  return (u8)((byte0 & 0xFC) | ((pn_len - 1) & 0x3));
}

/* Copy a CID into h (len already validated <= QUIC_MAX_CID_LEN). */
static void set_cid(u8 *dst, const u8 *src, usz len) {
  for (usz i = 0; i < len; i++) dst[i] = src[i];
}

/* True if both CIDs are within the QUIC max length. */
static int cids_ok(const quic_lhdr_desc *d) {
  return d->dcid.n <= QUIC_MAX_CID_LEN && d->scid.n <= QUIC_MAX_CID_LEN;
}

/* Build byte0+version+DCID+SCID via the invariant builder, then overwrite
 * byte0 with the caller's value (pn_len-adjusted). Returns bytes or 0. */
static usz lhdr_put_prefix(const quic_lhdr_desc *d, quic_obuf *out) {
  quic_header h = {0};
  usz         w;
  if (!cids_ok(d)) return 0;
  h.version  = d->version;
  h.dcid_len = (u8)d->dcid.n;
  h.scid_len = (u8)d->scid.n;
  set_cid(h.dcid, d->dcid.p, d->dcid.n);
  set_cid(h.scid, d->scid.p, d->scid.n);
  w = quic_header_build_long(out->p, out->cap, &h);
  if (w != 5 + 1 + d->dcid.n + 1 + d->scid.n) return 0;
  out->p[0] = quic_lhdr_byte0_pnlen(d->byte0, d->pn_len);
  return w;
}

/* Initial-only Token Length(varint)+Token at out->len. Returns 1 ok, 0
 * overflow. */
static int put_token(const quic_lhdr_desc *d, quic_obuf *out) {
  usz w;
  if (!d->is_initial) return 1;
  w = quic_inittoken_put(out->p + out->len, out->cap - out->len, d->token);
  if (w == 0) return 0;
  out->len += w;
  return 1;
}

/* Length(varint) = pn_len + payload_len + 16 (AEAD tag, RFC 9001), recording
 * its offset, then the truncated packet number. Returns 1 ok, 0 overflow. */
static int put_len_pn(
    const quic_lhdr_desc *d, quic_obuf *out, usz *length_off_out) {
  u64 remaining   = (u64)d->pn_len + d->payload_len + 16;
  *length_off_out = out->len;
  if (!quic_varint_put(quic_mspan_of(out->p, out->cap), &out->len, remaining))
    return 0;
  if (out->len + d->pn_len > out->cap) return 0;
  out->len += quic_pnum_encode(out->p + out->len, d->pn, d->pn_len);
  return 1;
}

/* Append Token (Initial only), Length, and packet number after the prefix. */
static int put_body(
    const quic_lhdr_desc *d, quic_obuf *out, usz *length_off_out) {
  return put_token(d, out) && put_len_pn(d, out, length_off_out);
}

usz quic_lhdr_build(
    const quic_lhdr_desc *d, quic_obuf *out, usz *length_off_out) {
  out->len = lhdr_put_prefix(d, out);
  if (out->len == 0) return 0;
  if (!put_body(d, out, length_off_out)) return 0;
  return out->len;
}
