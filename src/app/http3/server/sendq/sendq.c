#include "app/http3/server/sendq/sendq.h"

#include "common/bytes/util/num.h"

void wired_sendq_init(wired_sendq* q, const u8* p, usz len, usz chunk) {
  q->p     = p;
  q->len   = len;
  q->cur   = 0;
  q->chunk = chunk;
  q->cap   = 0;
}

void wired_sendq_set_ring(wired_sendq* q, usz cap) { q->cap = cap; }

const u8* wired_sendq_slice_data(
    const wired_sendq* q, const wired_sendq_slice* sl) {
  if (!q->cap) return q->p + sl->offset;
  return q->p + sl->offset % q->cap;
}

/* Bytes remaining from the cursor, capped at one chunk -- and, on a ring,
 * at the wrap, so a slice's bytes are always contiguous in storage. */
static usz sendq_take(const wired_sendq* q) {
  usz n = quic_u64_min(q->len - q->cur, q->chunk);
  if (q->cap) n = quic_u64_min(n, q->cap - q->cur % q->cap);
  return n;
}

int wired_sendq_next(wired_sendq* q, wired_sendq_slice* out) {
  usz n = sendq_take(q);
  if (q->cur >= q->len) return 0;
  out->offset = q->cur;
  out->len    = n;
  q->cur += n;
  out->fin = q->cur >= q->len;
  return 1;
}

int wired_sendq_all_sent(const wired_sendq* q) { return q->cur >= q->len; }
