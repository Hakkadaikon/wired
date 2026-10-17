#include "app/qpack/qpackdyn/enc_stream_impl.h"

static int  rx_trim(const qdyn_encrx* rx, u64* off, wired_span* d);
static void rx_mark(qdyn_encrx* rx, usz i, int v);
static int  rx_store(qdyn_encrx* rx, u64 off, wired_span d);

/* RFC 9000 2.2: drop the part of d below base (already consumed). 0 when
 * nothing new remains. */
static int rx_trim(const qdyn_encrx* rx, u64* off, wired_span* d) {
  u64 drop = *off < rx->base ? rx->base - *off : 0;
  if (drop >= d->n) return 0;
  d->p += drop;
  d->n -= (usz)drop;
  *off += drop;
  return 1;
}

/* Bit i of the received-byte bitmap. */
int qdyn_rx_has(const qdyn_encrx* rx, usz i) {
  return (rx->have[i / 8] >> (i % 8)) & 1;
}

static void rx_mark(qdyn_encrx* rx, usz i, int v) {
  u8 m            = (u8)(1u << (i % 8));
  rx->have[i / 8] = (u8)((rx->have[i / 8] & ~m) | (v ? m : 0));
}

/* Write d at off into the window; 0 if it reaches past the window. */
static int rx_store(qdyn_encrx* rx, u64 off, wired_span d) {
  u64 at = off - rx->base;
  if (at + d.n > QDYN_ENCRX_CAP) return 0;
  bytes_memcpy(rx->buf + at, d.p, d.n);
  for (usz i = 0; i < d.n; i++) rx_mark(rx, (usz)at + i, 1);
  rx->hi = (usz)u64_max(rx->hi, at + d.n);
  return 1;
}

int qdyn_rx_land(qdyn_encrx* rx, u64 off, wired_span d) {
  return !rx_trim(rx, &off, &d) || rx_store(rx, off, d);
}
