#include "transport/packet/header/packet/retry.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* Append a length-prefixed CID; returns 1 ok, 0 if no room. */
static int retry_put_cid(quic_obuf *out, quic_span cid) {
  if (out->len + 1 + cid.n > out->cap) return 0;
  out->p[out->len] = (u8)cid.n;
  out->len += 1;
  return quic_put_bytes(out->p, out->cap, &out->len, cid.p, cid.n);
}

/* True if the whole Retry packet fits in cap. */
static int retry_fits(usz cap, const quic_retry_desc *d) {
  usz need =
      5 + 1 + d->dcid.n + 1 + d->scid.n + d->token.n + QUIC_RETRY_TAG_LEN;
  return need <= cap;
}

usz quic_retry_build(u8 *buf, usz cap, const quic_retry_desc *d) {
  quic_obuf out = quic_obuf_of(buf, cap);
  out.len       = 5;
  if (!retry_fits(cap, d)) return 0;
  buf[0] = 0xF0; /* RFC 9000 17.2.5: long form, fixed bit, type Retry (0x3) */
  quic_put_be32(buf + 1, d->version);
  retry_put_cid(&out, d->dcid); /* room checked above */
  retry_put_cid(&out, d->scid);
  quic_put_bytes(out.p, out.cap, &out.len, d->token.p, d->token.n);
  quic_put_bytes(out.p, out.cap, &out.len, d->tag, QUIC_RETRY_TAG_LEN);
  return out.len;
}

/* Read a length-prefixed CID into dst->p/dst->n; 1 ok, 0 truncated. */
static int retry_take_cid(quic_span buf, usz *off, quic_mspan *dst) {
  u8 len;
  if (*off >= buf.n) return 0;
  len = buf.p[*off];
  if (len > QUIC_MAX_CID_LEN) return 0;
  *off += 1;
  dst->n = len;
  return quic_take_bytes(buf.p, buf.n, off, dst->p, len);
}

/* True if a long-form Retry byte0 with a token of >= 0 bytes can follow. */
static int retry_head_ok(const u8 *buf, usz n) {
  if (n < 5 + 1 + 1 + QUIC_RETRY_TAG_LEN) return 0;
  return (buf[0] & 0xF0) == 0xF0;
}

/* Read both CIDs at *off; returns 1 ok, 0 if either is truncated. */
static int retry_take_cids(quic_span buf, usz *off, quic_retry_packet *r) {
  quic_mspan d = quic_mspan_of(r->dcid, 0);
  quic_mspan s = quic_mspan_of(r->scid, 0);
  if (!retry_take_cid(buf, off, &d)) return 0;
  if (!retry_take_cid(buf, off, &s)) return 0;
  r->dcid_len = (u8)d.n;
  r->scid_len = (u8)s.n;
  return 1;
}

/* With CIDs consumed up to off, split the remainder into token + tag.
 * Returns 1 ok, 0 if no room is left for the 16-byte tag. */
static int take_token_tag(quic_span buf, usz off, quic_retry_packet *r) {
  usz tag_off = buf.n - QUIC_RETRY_TAG_LEN;
  if (off > tag_off) return 0;
  r->token     = buf.p + off;
  r->token_len = tag_off - off;
  return quic_take_bytes(buf.p, buf.n, &tag_off, r->tag, QUIC_RETRY_TAG_LEN);
}

/* Parse version, both CIDs and token+tag, the byte0/length gate already
 * passed. Returns 1 ok, 0 truncated. */
static int retry_parse_after_head(const u8 *buf, usz n, quic_retry_packet *r) {
  usz off    = 5;
  r->version = ((u32)buf[1] << 24) | ((u32)buf[2] << 16) | ((u32)buf[3] << 8) |
               (u32)buf[4];
  if (!retry_take_cids(quic_span_of(buf, n), &off, r)) return 0;
  return take_token_tag(quic_span_of(buf, n), off, r);
}

usz quic_retry_parse(const u8 *buf, usz n, quic_retry_packet *r) {
  if (!retry_head_ok(buf, n)) return 0;
  return retry_parse_after_head(buf, n, r) ? n : 0;
}
