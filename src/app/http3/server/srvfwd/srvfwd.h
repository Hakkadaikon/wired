#ifndef WIRED_SRVFWD_SRVFWD_H
#define WIRED_SRVFWD_SRVFWD_H

#include "transport/io/xdp/xdpframe/xdpframe.h"
#include "transport/io/xdp/xsksetup/xsksetup.h"

/** @file
 * Bounded single-producer/single-consumer ring that hands one received
 * AF_XDP datagram from the worker whose queue it arrived on to the worker
 * owning its connection (RFC 9000 9: a path change may move a connection's
 * packets to any rx queue, and the kernel only delivers to that queue's own
 * XSK). An N-worker run keeps N*N rings, one per (owner, receiver) pair, so
 * every ring has exactly one producer thread and one consumer thread: no
 * compare-and-swap, no lock, and a full ring drops (counted) instead of
 * blocking the datapath. An MPSC ring per owner would need a CAS on every
 * push for the same job.
 *
 * Memory ordering (same idiom as srvinbox.c and xskring.c): prod is stored
 * only by the producer, with RELEASE after the slot is written; the consumer
 * loads it with ACQUIRE before reading the slot. cons is stored only by the
 * consumer, with RELEASE after it is done with the slot; the producer loads
 * it with ACQUIRE before overwriting one. Both counters run free and wrap
 * (u32), so prod - cons is the fill level. An all-zero ring is empty. */

/** Ring depth, a power of two: one full srvrun receive batch (16) for a
 * single owner fits without a drop. */
#define SRVFWD_DEPTH 16u

/** One forwarded datagram: the parsed frame's addressing (peer address and
 * MAC, our MAC and IP, so the owner can reply over its own XSK) and a copy
 * of the payload; rx.payload points at buf. */
typedef struct {
  xdpframe_rx rx;
  u8          buf[XSKSETUP_FRAME_SIZE];
} srvfwd_slot;

/** One (owner, receiver) ring.
 * shortcut: prod, cons and drops share a cache line (as in srvinbox), so
 * producer and consumer bounce it; pad them apart if a profile shows it.
 * shortcut: drops is read only by tests; no stats output reports it (the
 * multi-queue driver has none); print it with the XDP stats if needed. */
typedef struct srvfwd_ring {
  srvfwd_slot slots[SRVFWD_DEPTH];
  u32         prod;  /**< free-running publish counter, producer-owned */
  u32         cons;  /**< free-running release counter, consumer-owned */
  u32         drops; /**< pushes refused because the ring was full */
} srvfwd_ring;

/** Producer side: copy rx (addressing and payload) into the next slot and
 * publish it. A full ring, or a payload longer than a frame, is dropped and
 * counted in r->drops.
 * @return 1 published, 0 dropped */
int srvfwd_push(srvfwd_ring* r, const xdpframe_rx* rx);

/** Consumer side: the oldest published datagram (its payload points into
 * the ring), or 0 when the ring is empty. Stays queued until srvfwd_pop. */
const xdpframe_rx* srvfwd_peek(srvfwd_ring* r);

/** Consumer side: release the datagram srvfwd_peek returned. */
void srvfwd_pop(srvfwd_ring* r);

#endif
