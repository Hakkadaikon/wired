#ifndef WIRED_SRVINBOX_SRVINBOX_H
#define WIRED_SRVINBOX_SRVINBOX_H

#include "common/platform/sys/syscall.h"

/** @file
 * SPSC ring for worker-to-worker broadcast handoff (Phase E). One ring
 * carries best-effort datagram-sized messages from exactly one producer
 * worker to exactly one consumer worker; an N-worker mesh is N*N of these
 * (srvrun.c's broadcast registry owns the mesh, this file only owns one
 * ring's push/pop contract).
 *
 * Same free-running-counter + ACQUIRE/RELEASE + look-then-reload idiom as
 * transport/io/xdp/xskring/xskring.c, specialized to a fixed-size datagram
 * slot instead of a generic descriptor array: push/pop do their own
 * check+write+publish / check+read+release in one call each, since a
 * datagram producer/consumer never needs to split reservation from
 * publication the way the AF_XDP rings do. Unlike xskring's quic_xskring
 * side struct, there is no per-side cached_prod/cached_cons field -- push/
 * pop are stateless across calls, so every full/empty look re-reads the
 * shared prod/cons cell (still just one extra ACQUIRE load in the common
 * case, since the "reload" only ever runs when the first look already
 * showed full/empty). */

/** Ring capacity; must stay a power of two (WIRED_SRVINBOX_DEPTH - 1 is used
 * as the index mask). */
#define WIRED_SRVINBOX_DEPTH 4u

/** Max payload bytes one slot holds -- sized for one QUIC datagram
 * (srvrun's own dg_pending_buf is 1200 bytes; this matches). */
#define WIRED_SRVINBOX_SLOT_MAX 1200u

/** One ring slot: a datagram payload and its length. */
typedef struct {
  u8  buf[WIRED_SRVINBOX_SLOT_MAX]; /**< payload bytes */
  usz len;                          /**< valid byte count in buf */
} wired_srvinbox_slot;

/** A single-producer/single-consumer ring of depth WIRED_SRVINBOX_DEPTH.
 * prod is written only by the producer (RELEASE on publish), read by the
 * consumer (ACQUIRE) to decide whether a pop has a message to read. cons is
 * written only by the consumer (RELEASE on release), read by the producer
 * (ACQUIRE) to decide whether a push has room -- the SPSC contract is
 * structural: exactly one thread may ever call push, exactly one (a
 * different one) may ever call pop. */
typedef struct {
  wired_srvinbox_slot slots[WIRED_SRVINBOX_DEPTH]; /**< ring storage */
  u32                 prod; /**< free-running publish counter, producer-owned */
  u32                 cons; /**< free-running release counter, consumer-owned */
} wired_srvinbox_ring;

/** Zero-initialize r (prod = cons = 0, empty ring). */
void wired_srvinbox_ring_init(wired_srvinbox_ring* r);

/** Push one message (producer side only). If the ring looks full, cons is
 * re-read with ACQUIRE and the fullness re-checked once before dropping --
 * the same look-then-recheck idiom as quic_xskring_prod_reserve, folded
 * into one call since a datagram producer never needs a separate
 * reserve/submit split.
 * @param r ring to push into
 * @param data payload bytes, copied into the slot
 * @param len payload length; > WIRED_SRVINBOX_SLOT_MAX is rejected (0
 *   returned, nothing sent)
 * @return 1 if the message was published, 0 if dropped (ring full after
 *   the reload, or len too large) */
int wired_srvinbox_push(wired_srvinbox_ring* r, const u8* data, usz len);

/** Pop one message (consumer side only) into out_buf. If the ring looks
 * empty, prod is re-read with ACQUIRE and re-checked once before reporting
 * empty -- mirrors quic_xskring_cons_peek's look-then-recheck idiom.
 * out_cap must be >= the popped message's length or nothing is popped (the
 * slot stays queued, so a caller that always passes a WIRED_SRVINBOX_SLOT_MAX
 * buffer never hits this): this SDK's callers all forward straight into a
 * srvrun_queue_datagram-sized buffer, so undersizing is not expected to
 * happen in practice.
 * @param r ring to pop from
 * @param out_buf destination for the payload bytes
 * @param out_cap capacity of out_buf
 * @return number of bytes popped (== the message's length), 0 if the ring
 *   was empty or out_buf was too small to hold the next message */
usz wired_srvinbox_pop(wired_srvinbox_ring* r, u8* out_buf, usz out_cap);

#endif
