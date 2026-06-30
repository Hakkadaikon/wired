#include "transport/packet/frame/frame/ncid.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/varint/varint.h"

/* The frame is well-formed if the CID length is in range and a peer cannot
 * be told to retire a sequence number it was never issued. */
static int ncid_valid(const quic_ncid_frame *f) {
  return f->cid_len <= QUIC_NCID_MAX_LEN && f->retire_prior_to <= f->seq;
}

/* Write type, seq, retire_prior_to varints. Returns 1 ok, 0 on overflow. */
static int put_ncid_head(u8 *buf, usz cap, usz *off, const quic_ncid_frame *f) {
  if (!quic_varint_put(buf, cap, off, QUIC_FRAME_NEW_CID)) return 0;
  if (!quic_varint_put(buf, cap, off, f->seq)) return 0;
  return quic_varint_put(buf, cap, off, f->retire_prior_to);
}

/* Write the length byte, the CID, and the reset token. */
static int put_ncid_body(u8 *buf, usz cap, usz *off, const quic_ncid_frame *f) {
  if (*off >= cap) return 0;
  buf[(*off)++] = f->cid_len;
  if (!quic_put_bytes(buf, cap, off, f->cid, f->cid_len)) return 0;
  return quic_put_bytes(buf, cap, off, f->token, QUIC_NCID_TOKEN);
}

/* Write head then body. Returns 1 ok, 0 on overflow. */
static int put_ncid(u8 *buf, usz cap, usz *off, const quic_ncid_frame *f) {
  if (!put_ncid_head(buf, cap, off, f)) return 0;
  return put_ncid_body(buf, cap, off, f);
}

usz quic_ncid_encode(u8 *buf, usz cap, const quic_ncid_frame *f) {
  usz off = 0;
  if (!ncid_valid(f)) return 0;
  if (!put_ncid(buf, cap, &off, f)) return 0;
  return off;
}

/* Read seq and retire_prior_to varints. Returns 1 ok, 0 bad. */
static int take_ncid_head(const u8 *buf, usz n, usz *off, quic_ncid_frame *f) {
  if (!quic_varint_take(buf, n, off, &f->seq)) return 0;
  return quic_varint_take(buf, n, off, &f->retire_prior_to);
}

/* The CID length byte at *off is present and within the QUIC maximum. */
static int cid_len_ok(const u8 *buf, usz n, usz off) {
  return off < n && buf[off] <= QUIC_NCID_MAX_LEN;
}

/* Read the length byte (bounded), the CID, and the reset token. */
static int take_ncid_body(const u8 *buf, usz n, usz *off, quic_ncid_frame *f) {
  if (!cid_len_ok(buf, n, *off)) return 0;
  f->cid_len = buf[(*off)++];
  if (!quic_take_bytes(buf, n, off, f->cid, f->cid_len)) return 0;
  return quic_take_bytes(buf, n, off, f->token, QUIC_NCID_TOKEN);
}

usz quic_ncid_decode(const u8 *buf, usz n, quic_ncid_frame *f) {
  usz off = 1; /* type byte */
  if (!take_ncid_head(buf, n, &off, f)) return 0;
  if (!take_ncid_body(buf, n, &off, f)) return 0;
  return off;
}
