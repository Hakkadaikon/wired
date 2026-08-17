#include "transport/packet/header/packet/vneg.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* Append a length-prefixed CID; returns 1 ok, 0 if no room. */
static int vneg_put_cid(wired_obuf* out, wired_span cid) {
  if (out->len + 1 + cid.n > out->cap) return 0;
  out->p[out->len] = (u8)cid.n;
  out->len += 1;
  return bytes_put(
      wired_mspan_of(out->p, out->cap), &out->len, wired_span_of(cid.p, cid.n));
}

/* True if the whole VN packet fits in cap and has at least one version. */
static int vneg_fits(usz cap, const vneg_desc* d) {
  usz need = 5 + 1 + d->dcid.n + 1 + d->scid.n + d->count * 4;
  return d->count != 0 && need <= cap;
}

/* Append the supported versions as 4 big-endian bytes each (room checked). */
static void put_versions(wired_obuf* out, const vneg_desc* d) {
  for (usz i = 0; i < d->count; i++) {
    be_put_be32(out->p + out->len, d->versions[i]);
    out->len += 4;
  }
}

usz vneg_build(u8* buf, usz cap, const vneg_desc* d) {
  wired_obuf out = obuf_of(buf, cap);
  out.len        = 5;
  if (!vneg_fits(cap, d)) return 0;
  buf[0] = 0x80; /* RFC 8999 6: high bit set; remaining bits unused here */
  be_put_be32(buf + 1, 0);     /* Version field 0 marks Version Negotiation */
  vneg_put_cid(&out, d->dcid); /* room checked above */
  vneg_put_cid(&out, d->scid);
  put_versions(&out, d);
  return out.len;
}

/* Read a length-prefixed CID into dst->p/dst->n; 1 ok, 0 truncated. */
static int vneg_take_cid(wired_span buf, usz* off, wired_mspan* dst) {
  u8 len;
  if (*off >= buf.n) return 0;
  len = buf.p[*off];
  if (len > WIRED_MAX_CID_LEN) return 0;
  *off += 1;
  dst->n = len;
  return bytes_take(
      wired_span_of(buf.p, buf.n), off, wired_mspan_of(dst->p, len));
}

/* True if the 4-byte Version field at buf+1 is all zero. */
static int version_zero(const u8* buf) {
  u32 ver = ((u32)buf[1] << 24) | ((u32)buf[2] << 16) | ((u32)buf[3] << 8) |
            (u32)buf[4];
  return ver == 0;
}

/* True if byte0 is long form, n holds a header, and the Version field is 0. */
static int vneg_head_ok(const u8* buf, usz n) {
  if (n < 7) return 0;
  if (!(buf[0] & 0x80)) return 0;
  return version_zero(buf);
}

/* Read both CIDs at *off; returns 1 ok, 0 truncated. */
static int vneg_take_cids(wired_span buf, usz* off, vneg_packet* v) {
  wired_mspan d = wired_mspan_of(v->dcid, 0);
  wired_mspan s = wired_mspan_of(v->scid, 0);
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
static int vneg_parse_after_head(const u8* buf, usz n, vneg_packet* v) {
  usz off = 5;
  usz rest;
  if (!vneg_take_cids(wired_span_of(buf, n), &off, v)) return 0;
  rest = n - off;
  if (!versions_whole(rest)) return 0;
  v->versions = buf + off;
  v->count    = rest / 4;
  return 1;
}

usz vneg_parse(const u8* buf, usz n, vneg_packet* v) {
  if (!vneg_head_ok(buf, n)) return 0;
  return vneg_parse_after_head(buf, n, v) ? n : 0;
}

usz vneg_respond(u8* buf, usz cap, const vneg_desc* recv) {
  /* Swap: response DCID = received SCID, response SCID = received DCID. */
  vneg_desc d = {recv->scid, recv->dcid, recv->versions, recv->count};
  return vneg_build(buf, cap, &d);
}
