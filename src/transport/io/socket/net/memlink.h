#ifndef QUIC_NET_MEMLINK_H
#define QUIC_NET_MEMLINK_H

#include "common/platform/sys/syscall.h"

/* An in-process datagram link: a fixed-capacity FIFO of byte buffers that
 * carries packets between two endpoints entirely in user memory. No socket,
 * no syscall — this is how the kernel-free end-to-end path moves bytes. */

#define QUIC_MEMLINK_SLOTS 16
#define QUIC_MEMLINK_MTU 1500

/** One queued datagram's bytes and length. */
typedef struct {
  u8  data[QUIC_MEMLINK_MTU];
  usz len;
} memlink_dgram;

/** A fixed-capacity FIFO of datagrams, carrying packets in user memory. */
typedef struct {
  memlink_dgram slots[QUIC_MEMLINK_SLOTS];
  usz           head, tail, count;
} memlink;

void memlink_init(memlink* l);

/* Enqueue a datagram. Returns 1 on success, 0 if full or oversize. */
int memlink_send(memlink* l, const u8* buf, usz len);

/* Dequeue the oldest datagram into out (cap bytes). Returns its length, or
 * 0 if the link is empty or out is too small. */
usz memlink_recv(memlink* l, u8* out, usz cap);

#endif
