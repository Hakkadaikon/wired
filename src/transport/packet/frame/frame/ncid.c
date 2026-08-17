#include "transport/packet/frame/frame/ncid.h"

#include "common/bytes/span/span.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/varint/varint.h"

/* The frame is well-formed if the CID length is in range and a peer cannot
 * be told to retire a sequence number it was never issued. */
static int ncid_valid(const ncid_frame* f) {
  return f->cid_len <= NCID_MAX_LEN && f->retire_prior_to <= f->seq;
}

/* Write type, seq, retire_prior_to varints. Returns 1 ok, 0 on overflow. */
static int put_ncid_head(wired_obuf* o, const ncid_frame* f) {
  if (!varint_put(wired_mspan_of(o->p, o->cap), &o->len, FRAME_NEW_CID))
    return 0;
  if (!varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->seq)) return 0;
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->retire_prior_to);
}

/* Write the length byte, the CID, and the reset token. */
static int put_ncid_body(wired_obuf* o, const ncid_frame* f) {
  if (o->len >= o->cap) return 0;
  o->p[o->len++] = f->cid_len;
  if (!bytes_put(
          wired_mspan_of(o->p, o->cap), &o->len,
          wired_span_of(f->cid, f->cid_len)))
    return 0;
  return bytes_put(
      wired_mspan_of(o->p, o->cap), &o->len,
      wired_span_of(f->token, NCID_TOKEN));
}

/* Write head then body. Returns 1 ok, 0 on overflow. */
static int put_ncid(wired_obuf* o, const ncid_frame* f) {
  if (!put_ncid_head(o, f)) return 0;
  return put_ncid_body(o, f);
}

usz ncid_encode(u8* buf, usz cap, const ncid_frame* f) {
  wired_obuf o = obuf_of(buf, cap);
  if (!ncid_valid(f)) return 0;
  if (!put_ncid(&o, f)) return 0;
  return o.len;
}

/* Read seq and retire_prior_to varints. Returns 1 ok, 0 bad. */
static int take_ncid_head(wired_span in, usz* off, ncid_frame* f) {
  if (!varint_take(wired_span_of(in.p, in.n), off, &f->seq)) return 0;
  return varint_take(wired_span_of(in.p, in.n), off, &f->retire_prior_to);
}

/* The CID length byte at *off is present and within the QUIC maximum. */
static int cid_len_ok(const u8* buf, usz n, usz off) {
  return off < n && buf[off] <= NCID_MAX_LEN;
}

/* Read the length byte (bounded), the CID, and the reset token. */
static int take_ncid_body(wired_span in, usz* off, ncid_frame* f) {
  if (!cid_len_ok(in.p, in.n, *off)) return 0;
  f->cid_len = in.p[(*off)++];
  if (!bytes_take(
          wired_span_of(in.p, in.n), off, wired_mspan_of(f->cid, f->cid_len)))
    return 0;
  return bytes_take(
      wired_span_of(in.p, in.n), off, wired_mspan_of(f->token, NCID_TOKEN));
}

usz ncid_decode(const u8* buf, usz n, ncid_frame* f) {
  wired_span in  = wired_span_of(buf, n);
  usz        off = 1; /* type byte */
  if (!take_ncid_head(in, &off, f)) return 0;
  if (!take_ncid_body(in, &off, f)) return 0;
  return off;
}
