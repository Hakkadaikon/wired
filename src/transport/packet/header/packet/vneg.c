#include "transport/packet/header/packet/vneg.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* Append a length-prefixed CID; returns 1 ok, 0 if no room. */
static int vneg_put_cid(quic_obuf *out, quic_span cid) {
  if (out->len + 1 + cid.n > out->cap) return 0;
  out->p[out->len] = (u8)cid.n;
  out->len += 1;
  return quic_put_bytes(
      quic_mspan_of(out->p, out->cap), &out->len, quic_span_of(cid.p, cid.n));
}

/* True if the whole VN packet fits in cap and has at least one version. */
static int vneg_fits(usz cap, const quic_vneg_desc *d) {
  usz need = 5 + 1 + d->dcid.n + 1 + d->scid.n + d->count * 4;
  return d->count != 0 && need <= cap;
}

/* Append the supported versions as 4 big-endian bytes each (room checked). */
static void put_versions(quic_obuf *out, const quic_vneg_desc *d) {
  for (usz i = 0; i < d->count; i++) {
    quic_put_be32(out->p + out->len, d->versions[i]);
    out->len += 4;
  }
}

usz quic_vneg_build(u8 *buf, usz cap, const quic_vneg_desc *d) {
  quic_obuf out = quic_obuf_of(buf, cap);
  out.len       = 5;
  if (!vneg_fits(cap, d)) return 0;
  buf[0] = 0x80; /* RFC 8999 6: high bit set; remaining bits unused here */
  quic_put_be32(buf + 1, 0);   /* Version field 0 marks Version Negotiation */
  vneg_put_cid(&out, d->dcid); /* room checked above */
  vneg_put_cid(&out, d->scid);
  put_versions(&out, d);
  return out.len;
}

/* Read a length-prefixed CID into dst->p/dst->n; 1 ok, 0 truncated. */
static int vneg_take_cid(quic_span buf, usz *off, quic_mspan *dst) {
  u8 len;
  if (*off >= buf.n) return 0;
  len = buf.p[*off];
  if (len > QUIC_MAX_CID_LEN) return 0;
  *off += 1;
  dst->n = len;
  return quic_take_bytes(
      quic_span_of(buf.p, buf.n), off, quic_mspan_of(dst->p, len));
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
static int vneg_take_cids(quic_span buf, usz *off, quic_vneg_packet *v) {
  quic_mspan d = quic_mspan_of(v->dcid, 0);
  quic_mspan s = quic_mspan_of(v->scid, 0);
  if (!vneg_take_cid(buf, off, &d)) return 0;
  if (!vneg_take_cid(buf, off, &s)) return 0;
  v->dcid_len = (u8)d.n;
  v->scid_len = (u8)s.n;
  return 1;
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
  if (!vneg_take_cids(quic_span_of(buf, n), &off, v)) return 0;
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

usz quic_vneg_respond(u8 *buf, usz cap, const quic_vneg_desc *recv) {
  /* Swap: response DCID = received SCID, response SCID = received DCID. */
  quic_vneg_desc d = {recv->scid, recv->dcid, recv->versions, recv->count};
  return quic_vneg_build(buf, cap, &d);
}
