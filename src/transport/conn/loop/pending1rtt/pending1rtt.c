#include "transport/conn/loop/pending1rtt/pending1rtt.h"

#include "common/bytes/util/bytes.h"

void pending1rtt_init(pending1rtt* q) { q->count = 0; }

/* RFC 9001 5.7 */
int pending1rtt_should_defer(int handshake_complete) {
  return !handshake_complete;
}

/* 1 if len and the current queue depth both leave room for one more entry. */
static int pending1rtt_fits(const pending1rtt* q, usz len) {
  return len <= PENDING1RTT_MAX_LEN && q->count < PENDING1RTT_CAP;
}

int pending1rtt_store(pending1rtt* q, const u8* data, usz len) {
  if (!pending1rtt_fits(q, len)) return 0;
  bytes_memcpy(q->buf[q->count], data, len);
  q->len[q->count] = len;
  q->count++;
  return 1;
}

usz pending1rtt_count(const pending1rtt* q) { return q->count; }

int pending1rtt_peek(const pending1rtt* q, usz i, const u8** data, usz* len) {
  if (i >= q->count) return 0;
  *data = q->buf[i];
  *len  = q->len[i];
  return 1;
}

void pending1rtt_clear(pending1rtt* q) { q->count = 0; }
