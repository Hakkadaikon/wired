#include "transport/packet/header/packet/header.h"

#include "common/bytes/span/span.h"

/* Copy len bytes src->dst unconditionally (len already validated). */
static void copy_cid(u8 *dst, const u8 *src, u8 len) {
  for (u8 i = 0; i < len; i++) dst[i] = src[i];
}

/* True if a CID of length len starting at off fits in n bytes and is
 * within the QUIC max CID length. */
static int cid_fits(u8 len, usz off, usz n) {
  return len <= QUIC_MAX_CID_LEN && off + 1 + (usz)len <= n;
}

/* Read one length-prefixed CID at buf. On success advances *off by 1+len,
 * copies the CID into dst->p and sets dst->n. Returns 1 ok, 0 truncated. */
static int read_cid(quic_span buf, usz *off, quic_mspan *dst) {
  u8 len;
  if (*off >= buf.n) return 0;
  len = buf.p[*off];
  if (!cid_fits(len, *off, buf.n)) return 0;
  dst->n = len;
  copy_cid(dst->p, buf.p + *off + 1, len);
  *off += 1 + (usz)len;
  return 1;
}

/* Read the length-prefixed DCID then SCID at *off into h. */
static int read_cids(quic_span buf, usz *off, wired_header *h) {
  quic_mspan d = quic_mspan_of(h->dcid, 0);
  quic_mspan s = quic_mspan_of(h->scid, 0);
  if (!read_cid(buf, off, &d)) return 0;
  if (!read_cid(buf, off, &s)) return 0;
  h->dcid_len = (u8)d.n;
  h->scid_len = (u8)s.n;
  return 1;
}

static usz parse_long(const u8 *buf, usz n, wired_header *h) {
  usz off      = 5; /* byte0 + 4-byte version */
  h->form      = QUIC_FORM_LONG;
  h->long_type = (buf[0] >> 4) & 0x3;
  h->version = ((u32)buf[1] << 24) | ((u32)buf[2] << 16) | ((u32)buf[3] << 8) |
               (u32)buf[4];
  if (!read_cids(quic_span_of(buf, n), &off, h)) return 0;
  return off;
}

/* Short header: byte0 then DCID of the connection's known local length
 * (the caller presets h->dcid_len). */
static usz parse_short(const u8 *buf, usz n, wired_header *h) {
  u8 dcid_len = h->dcid_len;
  if (!cid_fits(dcid_len, 0, n)) return 0;
  h->form = QUIC_FORM_SHORT;
  copy_cid(h->dcid, buf + 1, dcid_len);
  h->scid_len = 0;
  return 1 + (usz)dcid_len;
}

usz wired_header_parse(const u8 *buf, usz n, wired_header *h) {
  if (n == 0) return 0;
  if (buf[0] & 0x80) return parse_long(buf, n, h);
  return parse_short(buf, n, h);
}

/* Append a length-prefixed CID; advance out->len. Returns 1 ok, 0 no room. */
static int write_cid(quic_obuf *out, quic_span cid) {
  if (out->len + 1 + cid.n > out->cap) return 0;
  out->p[out->len] = (u8)cid.n;
  for (usz i = 0; i < cid.n; i++) out->p[out->len + 1 + i] = cid.p[i];
  out->len += 1 + cid.n;
  return 1;
}

/* Write byte0 (long form + fixed bit + type) and the 4-byte version into
 * buf (cap bytes). Returns 5 (bytes written) or 0 if it does not fit. */
static usz put_long_prefix(u8 *buf, usz cap, const wired_header *h) {
  if (cap < 5) return 0;
  buf[0] = 0xC0 | (u8)(h->long_type << 4);
  buf[1] = (u8)(h->version >> 24);
  buf[2] = (u8)(h->version >> 16);
  buf[3] = (u8)(h->version >> 8);
  buf[4] = (u8)h->version;
  return 5;
}

/* Append both CIDs (dcid then scid); zero out->len on overflow. */
static void write_cids(quic_obuf *out, const wired_header *h) {
  const quic_span cid[2] = {
      quic_span_of(h->dcid, h->dcid_len), quic_span_of(h->scid, h->scid_len)};
  for (usz i = 0; i < 2; i++)
    if (!write_cid(out, cid[i])) out->len = 0;
}

usz wired_header_build_long(u8 *buf, usz cap, const wired_header *h) {
  quic_obuf out = quic_obuf_of(buf, cap);
  out.len       = put_long_prefix(buf, cap, h);
  if (out.len != 0) write_cids(&out, h);
  return out.len;
}
