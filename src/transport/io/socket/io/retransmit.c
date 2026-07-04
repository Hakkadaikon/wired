#include "transport/io/socket/io/retransmit.h"

void quic_rtx_init(quic_rtx_queue* q) {
  q->head  = 0;
  q->tail  = 0;
  q->count = 0;
}

/* Copy len bytes into the slot at tail and advance. */
static void store(quic_rtx_queue* q, const u8* frame, usz len) {
  quic_rtx_frame* s = &q->slots[q->tail];
  for (usz i = 0; i < len; i++) s->data[i] = frame[i];
  s->len  = len;
  q->tail = (q->tail + 1) % QUIC_RTX_SLOTS;
  q->count++;
}

int quic_rtx_push(quic_rtx_queue* q, const u8* frame, usz len) {
  if (q->count == QUIC_RTX_SLOTS || len > QUIC_RTX_FRAME) return 0;
  store(q, frame, len);
  return 1;
}

/* Copy the head slot into out and advance. */
static usz take(quic_rtx_queue* q, u8* out) {
  quic_rtx_frame* s = &q->slots[q->head];
  for (usz i = 0; i < s->len; i++) out[i] = s->data[i];
  q->head = (q->head + 1) % QUIC_RTX_SLOTS;
  q->count--;
  return s->len;
}

usz quic_rtx_pop(quic_rtx_queue* q, u8* out, usz cap) {
  if (q->count == 0 || q->slots[q->head].len > cap) return 0;
  return take(q, out);
}
