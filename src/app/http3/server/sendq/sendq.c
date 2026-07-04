#include "app/http3/server/sendq/sendq.h"

void wired_sendq_init(wired_sendq* q, const u8* p, usz len, usz chunk) {
  q->p     = p;
  q->len   = len;
  q->cur   = 0;
  q->chunk = chunk;
}

/* Bytes remaining from the cursor, capped at one chunk. */
static usz sendq_take(const wired_sendq* q) {
  usz rem = q->len - q->cur;
  return rem < q->chunk ? rem : q->chunk;
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
