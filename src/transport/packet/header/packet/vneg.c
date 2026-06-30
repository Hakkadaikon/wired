#include "transport/packet/header/packet/vneg.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* Append a length-prefixed CID at *off; returns 1 ok, 0 if no room. */
static int vneg_put_cid(u8 *buf, usz cap, usz *off, const u8 *cid, u8 len) {
  if (*off + 1 + (usz)len > cap) return 0;
  buf[*off] = len;
  *off += 1;
  return quic_put_bytes(buf, cap, off, cid, len);
}

/* True if the whole VN packet fits in cap and has at least one version. */
static int vneg_fits(usz cap, u8 dcid_len, u8 scid_len, usz count) {
  usz need = 5 + 1 + (usz)dcid_len + 1 + (usz)scid_len + count * 4;
  return count != 0 && need <= cap;
}

/* Append count supported versions as 4 big-endian bytes each (room checked). */
static void put_versions(u8 *buf, usz *off, const u32 *versions, usz count) {
  for (usz i = 0; i < count; i++) {
    quic_put_be32(buf + *off, versions[i]);
    *off += 4;
  }
}

usz quic_vneg_build(
    u8        *buf,
    usz        cap,
    const u8  *dcid,
    u8         dcid_len,
    const u8  *scid,
    u8         scid_len,
    const u32 *versions,
    usz        count) {
  usz off = 5;
  if (!vneg_fits(cap, dcid_len, scid_len, count)) return 0;
  buf[0] = 0x80; /* RFC 8999 6: high bit set; remaining bits unused here */
  quic_put_be32(buf + 1, 0); /* Version field 0 marks Version Negotiation */
  vneg_put_cid(buf, cap, &off, dcid, dcid_len); /* room checked above */
  vneg_put_cid(buf, cap, &off, scid, scid_len);
  put_versions(buf, &off, versions, count);
  return off;
}

/* Read a length-prefixed CID at *off into dst/dst_len; 1 ok, 0 truncated. */
static int vneg_take_cid(const u8 *buf, usz n, usz *off, u8 *dst, u8 *dst_len) {
  u8 len;
  if (*off >= n) return 0;
  len = buf[*off];
  if (len > QUIC_MAX_CID_LEN) return 0;
  *off += 1;
  *dst_len = len;
  return quic_take_bytes(buf, n, off, dst, len);
}

/* True if the 4-byte Version field at buf+1 is all zero. */
static int version_zero(const u8 *buf) {
  u32 ver = ((u32)buf[1] << 24) | ((u32)buf[2] << 16) | ((u32)buf[3] << 8) |
            (u32)buf[4];
  return ver == 0;
}

/* True if byte0 is long form, n holds a header, and the Version field is 0. */
static int vneg_head_ok(const u8 *buf, usz n) {
  if (n < 7) return 0;
  if (!(buf[0] & 0x80)) return 0;
  return version_zero(buf);
}

/* Read both CIDs at *off; returns 1 ok, 0 truncated. */
static int vneg_take_cids(const u8 *buf, usz n, usz *off, quic_vneg_packet *v) {
  if (!vneg_take_cid(buf, n, off, v->dcid, &v->dcid_len)) return 0;
  return vneg_take_cid(buf, n, off, v->scid, &v->scid_len);
}

/* True if rest bytes form one or more whole 4-byte versions. */
static int versions_whole(usz rest) {
  if (rest == 0) return 0;
  return rest % 4 == 0;
}

/* Parse both CIDs and the supported-version list, header gate already passed.
 * Returns 1 ok, 0 if a CID is truncated or the version list is misaligned. */
static int vneg_parse_after_head(const u8 *buf, usz n, quic_vneg_packet *v) {
  usz off = 5;
  usz rest;
  if (!vneg_take_cids(buf, n, &off, v)) return 0;
  rest = n - off;
  if (!versions_whole(rest)) return 0;
  v->versions = buf + off;
  v->count    = rest / 4;
  return 1;
}

usz quic_vneg_parse(const u8 *buf, usz n, quic_vneg_packet *v) {
  if (!vneg_head_ok(buf, n)) return 0;
  return vneg_parse_after_head(buf, n, v) ? n : 0;
}

usz quic_vneg_respond(
    u8        *buf,
    usz        cap,
    const u8  *recv_dcid,
    u8         recv_dcid_len,
    const u8  *recv_scid,
    u8         recv_scid_len,
    const u32 *versions,
    usz        count) {
  /* Swap: response DCID = received SCID, response SCID = received DCID. */
  return quic_vneg_build(
      buf, cap, recv_scid, recv_scid_len, recv_dcid, recv_dcid_len, versions,
      count);
}
