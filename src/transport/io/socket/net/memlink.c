#include "transport/io/socket/net/memlink.h"

void quic_memlink_init(quic_memlink* l) {
  l->head  = 0;
  l->tail  = 0;
  l->count = 0;
}

/* Copy len bytes into the tail slot and advance. */
static void enqueue(quic_memlink* l, const u8* buf, usz len) {
  quic_memlink_dgram* d = &l->slots[l->tail];
  for (usz i = 0; i < len; i++) d->data[i] = buf[i];
  d->len  = len;
  l->tail = (l->tail + 1) % QUIC_MEMLINK_SLOTS;
  l->count++;
}

int quic_memlink_send(quic_memlink* l, const u8* buf, usz len) {
  if (l->count == QUIC_MEMLINK_SLOTS || len > QUIC_MEMLINK_MTU) return 0;
  enqueue(l, buf, len);
  return 1;
}

/* Copy the head slot into out and advance. */
static usz dequeue(quic_memlink* l, u8* out) {
  quic_memlink_dgram* d = &l->slots[l->head];
  for (usz i = 0; i < d->len; i++) out[i] = d->data[i];
  l->head = (l->head + 1) % QUIC_MEMLINK_SLOTS;
  l->count--;
  return d->len;
}

usz quic_memlink_recv(quic_memlink* l, u8* out, usz cap) {
  if (l->count == 0 || l->slots[l->head].len > cap) return 0;
  return dequeue(l, out);
}
