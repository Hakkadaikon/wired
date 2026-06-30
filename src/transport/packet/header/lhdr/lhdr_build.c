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
static void set_cid(u8 *dst, const u8 *src, u8 len) {
  for (u8 i = 0; i < len; i++) dst[i] = src[i];
}

/* True if both CIDs are within the QUIC max length. */
static int cids_ok(u8 dcid_len, u8 scid_len) {
  return dcid_len <= QUIC_MAX_CID_LEN && scid_len <= QUIC_MAX_CID_LEN;
}

/* Build byte0+version+DCID+SCID via the invariant builder, then overwrite
 * byte0 with the caller's value (pn_len-adjusted). Returns bytes or 0. */
static usz lhdr_put_prefix(
    u8       *out,
    usz       cap,
    u8        byte0,
    u32       version,
    const u8 *dcid,
    u8        dcid_len,
    const u8 *scid,
    u8        scid_len,
    u8        pn_len) {
  quic_header h = {0};
  usz         w;
  if (!cids_ok(dcid_len, scid_len)) return 0;
  h.version  = version;
  h.dcid_len = dcid_len;
  h.scid_len = scid_len;
  set_cid(h.dcid, dcid, dcid_len);
  set_cid(h.scid, scid, scid_len);
  w = quic_header_build_long(out, cap, &h);
  if (w != (usz)(5 + 1 + dcid_len + 1 + scid_len)) return 0;
  out[0] = quic_lhdr_byte0_pnlen(byte0, pn_len);
  return w;
}

/* Initial-only Token Length(varint)+Token at *off. Returns 1 ok, 0 overflow. */
static int put_token(
    u8       *out,
    usz       cap,
    usz      *off,
    int       is_initial,
    const u8 *token,
    usz       token_len) {
  usz w;
  if (!is_initial) return 1;
  w = quic_inittoken_put(out + *off, cap - *off, token, token_len);
  if (w == 0) return 0;
  *off += w;
  return 1;
}

/* Length(varint) = pn_len + payload_len + 16 (AEAD tag, RFC 9001), recording
 * its offset, then the truncated packet number. Returns 1 ok, 0 overflow. */
static int put_len_pn(
    u8  *out,
    usz  cap,
    usz *off,
    usz  payload_len,
    u64  pn,
    u8   pn_len,
    usz *length_off_out) {
  u64 remaining   = (u64)pn_len + payload_len + 16;
  *length_off_out = *off;
  if (!quic_varint_put(out, cap, off, remaining)) return 0;
  if (*off + pn_len > cap) return 0;
  *off += quic_pnum_encode(out + *off, pn, pn_len);
  return 1;
}

/* Append Token (Initial only), Length, and packet number after the prefix
 * at *off. Returns 1 ok, 0 on any overflow. */
static int put_body(
    u8       *out,
    usz       cap,
    usz      *off,
    int       is_initial,
    const u8 *token,
    usz       token_len,
    usz       payload_len,
    u64       pn,
    u8        pn_len,
    usz      *length_off_out) {
  return put_token(out, cap, off, is_initial, token, token_len) &&
         put_len_pn(out, cap, off, payload_len, pn, pn_len, length_off_out);
}

usz quic_lhdr_build(
    u8        byte0,
    u32       version,
    const u8 *dcid,
    u8        dcid_len,
    const u8 *scid,
    u8        scid_len,
    int       is_initial,
    const u8 *token,
    usz       token_len,
    usz       payload_len,
    u64       pn,
    u8        pn_len,
    u8       *out,
    usz       cap,
    usz      *hdr_len_out,
    usz      *length_off_out) {
  usz off = lhdr_put_prefix(
      out, cap, byte0, version, dcid, dcid_len, scid, scid_len, pn_len);
  if (off == 0) return 0;
  if (!put_body(
          out, cap, &off, is_initial, token, token_len, payload_len, pn, pn_len,
          length_off_out))
    return 0;
  *hdr_len_out = off;
  return off;
}
