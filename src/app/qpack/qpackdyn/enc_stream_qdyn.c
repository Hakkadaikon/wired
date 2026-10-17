#include "app/qpack/qpackdyn/enc_stream_impl.h"

static usz  qdyn_encrx_ready(const qdyn_encrx* rx);
static usz  rx_apply(qdyn_encrx* rx, qpack_dyn* t, u64 max, u16* err);
static u8   rx_have_byte(const qdyn_encrx* rx, usz i, usz bytes);
static void rx_shift_marks(qdyn_encrx* rx, usz n);
static void rx_slide(qdyn_encrx* rx, usz n);
static void qdyn_encrx_identify(qdyn_encrx* rx);
static void qdyn_encrx_settle(qdyn_encrx* rx, qpack_dyn* t, u64 max, u16* err);
static u16  qdyn_encrx_overflow(const qdyn_encrx* rx);

/* Bytes contiguous from base. */
static usz qdyn_encrx_ready(const qdyn_encrx* rx) {
  usz n = 0;
  while (n < rx->hi && qdyn_rx_has(rx, n)) n++;
  return n;
}

/* Apply the whole instructions in the contiguous prefix; bytes consumed. */
static usz rx_apply(qdyn_encrx* rx, qpack_dyn* t, u64 max, u16* err) {
  usz ready = qdyn_encrx_ready(rx), used = 0, n;
  do {
    n = qdyn_enc_apply(
        wired_span_of(rx->buf + used, ready - used), t, max, err);
    used += n;
  } while (n);
  return used;
}

/* Mark byte i of the first `bytes`, 0 past them. */
static u8 rx_have_byte(const qdyn_encrx* rx, usz i, usz bytes) {
  return i < bytes ? rx->have[i] : 0;
}

/* Shift the received-byte marks down by n a whole mark byte at a time,
 * clearing the vacated top (marks past hi are always clear). */
static void rx_shift_marks(qdyn_encrx* rx, usz n) {
  usz bytes = (rx->hi + 7) / 8, q = n / 8, r = n % 8;
  for (usz i = 0; i < bytes; i++)
    rx->have[i] = (u8)((rx_have_byte(rx, i + q, bytes) >> r) |
                       (rx_have_byte(rx, i + q + 1, bytes) << (8 - r)));
}

/* Slide the consumed prefix (n <= the contiguous bytes) out of the window:
 * the bytes and their marks move down by n, base up by n. */
static void rx_slide(qdyn_encrx* rx, usz n) {
  if (n == 0) return; /* nothing consumed: moving the window is pure cost */
  bytes_move_down(rx->buf, rx->buf + n, rx->hi - n);
  rx_shift_marks(rx, n);
  rx->hi -= n;
  rx->base += n;
}

void qdyn_encrx_take(qdyn_encrx* rx, u64 stream_id) {
  bytes_memset(rx->have, 0, (rx->hi + 7) / 8);
  rx->base      = 0;
  rx->hi        = 0;
  rx->type_len  = 0;
  rx->stream_id = stream_id;
}

/* RFC 9204 4.2 / RFC 9000 16: once the held stream's leading type varint is
 * whole, claim the stream (consuming the varint) if it is the encoder type,
 * else let it go -- its bytes belong to some other stream type. */
static void qdyn_encrx_identify(qdyn_encrx* rx) {
  u64 v;
  usz n = 0;
  if (!varint_take(wired_span_of(rx->buf, qdyn_encrx_ready(rx)), &n, &v))
    return;
  if (v != QDYN_ENC_STREAM_TYPE) {
    qdyn_encrx_take(rx, 0);
    return;
  }
  rx->type_len = n;
  rx_slide(rx, n);
}

/* Identify the held stream if still needed, then apply what a claimed one
 * has contiguous. */
static void qdyn_encrx_settle(qdyn_encrx* rx, qpack_dyn* t, u64 max, u16* err) {
  if (!rx->type_len) qdyn_encrx_identify(rx);
  if (rx->type_len) rx_slide(rx, rx_apply(rx, t, max, err));
}

/* d reached past the window: an error only on the claimed encoder stream
 * (a flow-control violation); an unidentified stream's bytes are not ours
 * to judge. */
static u16 qdyn_encrx_overflow(const qdyn_encrx* rx) {
  return rx->type_len ? QPACK_ENCODER_STREAM_ERROR : 0;
}

int qdyn_encrx_feed(
    qdyn_encrx* rx, u64 off, wired_span d, qpack_dyn* t, u64 max, u16* err) {
  u16 e = 0;
  if (!qdyn_rx_land(rx, off, d))
    e = qdyn_encrx_overflow(rx);
  else
    qdyn_encrx_settle(rx, t, max, &e);
  if (e) *err = e;
  return e == 0;
}

u64 qdyn_encrx_credit(const qdyn_encrx* rx) {
  return rx->base + QDYN_ENCRX_CAP;
}
