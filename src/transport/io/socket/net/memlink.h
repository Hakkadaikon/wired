#ifndef QUIC_NET_MEMLINK_H
#define QUIC_NET_MEMLINK_H

#include "common/platform/sys/syscall.h"

/* An in-process datagram link: a fixed-capacity FIFO of byte buffers that
 * carries packets between two endpoints entirely in user memory. No socket,
 * no syscall — this is how the kernel-free end-to-end path moves bytes. */

#define QUIC_MEMLINK_SLOTS 16
#define QUIC_MEMLINK_MTU   1500

typedef struct {
    u8 data[QUIC_MEMLINK_MTU];
    usz len;
} quic_memlink_dgram;

typedef struct {
    quic_memlink_dgram slots[QUIC_MEMLINK_SLOTS];
    usz head, tail, count;
} quic_memlink;

void quic_memlink_init(quic_memlink *l);

/* Enqueue a datagram. Returns 1 on success, 0 if full or oversize. */
int quic_memlink_send(quic_memlink *l, const u8 *buf, usz len);

/* Dequeue the oldest datagram into out (cap bytes). Returns its length, or
 * 0 if the link is empty or out is too small. */
usz quic_memlink_recv(quic_memlink *l, u8 *out, usz cap);

#endif
