#ifndef QUIC_XSKRING_H
#define QUIC_XSKRING_H

#include "common/platform/sys/syscall.h"

/** @file
 * SPSC ring operations shared by the four AF_XDP rings (fill/comp/rx/tx).
 * Producer and consumer indices are free-running u32 counters (never masked
 * in place); every accessor masks a raw index at the point of use, matching
 * the kernel's own ring protocol (linux/if_xdp.h descriptions of
 * XDP_UMEM_PGOFF_FILL_RING etc). This file operates purely on caller-owned
 * pointers: no mmap, no syscalls, so it is unit-testable against plain
 * local variables. */

/** AF_XDP descriptor (binary-compatible with linux/if_xdp.h struct
 * xdp_desc). Entry type of the rx/tx rings; fill/comp rings hold a bare u64
 * frame address instead. */
typedef struct {
  /** UMEM byte offset of the frame */
  u64 addr;
  /** frame byte length */
  u32 len;
  /** kernel flags, 0 on every frame this SDK produces */
  u32 options;
} quic_xdp_desc;

/** Raw mmap'd ring pointers as handed in by the caller (or, in tests, plain
 * local variables). producer/consumer are the shared index cells; desc is
 * the entry array (u64[] for fill/comp, quic_xdp_desc[] for rx/tx). */
typedef struct {
  /** shared producer index cell */
  u32* producer;
  /** shared consumer index cell */
  u32* consumer;
  /** entry array (u64[] for fill/comp, quic_xdp_desc[] for rx/tx) */
  void* desc;
  /** ring capacity, a power of two */
  u32 size;
} quic_xskring_view;

/** One SPSC ring side, caching the peer's last-known index so the hot path
 * avoids re-reading the shared cell on every call. */
typedef struct {
  /** shared producer index cell */
  u32* producer;
  /** shared consumer index cell */
  u32* consumer;
  /** entry array (u64[] for fill/comp, quic_xdp_desc[] for rx/tx) */
  void* desc;
  /** size - 1, masks a raw index into a slot */
  u32 mask;
  /** ring capacity, a power of two */
  u32 size;
  /** last-seen value of *producer */
  u32 cached_prod;
  /** last-seen value of *consumer */
  u32 cached_cons;
} quic_xskring;

/** Initialize r from a view. size must be a power of two. */
void quic_xskring_init(quic_xskring* r, const quic_xskring_view* v);

/** Producer side (feeding the fill ring, submitting to the tx ring).
 * Returns the number of slots actually granted (<= n): if the cached free
 * count is short, the consumer index is re-read with ACQUIRE and the free
 * count recomputed once before giving up. *idx receives the first granted
 * slot's raw (unmasked) index. */
u32 quic_xskring_prod_reserve(quic_xskring* r, u32 n, u32* idx);

/** Publish n previously reserved slots: advances cached_prod by n and
 * RELEASE-stores it to *producer. */
void quic_xskring_prod_submit(quic_xskring* r, u32 n);

/** Consumer side (draining the rx ring, reaping the comp ring).
 * Returns the number of slots actually available (<= n): if the cached
 * available count is short, the producer index is re-read with ACQUIRE and
 * the available count recomputed once before giving up. *idx receives the
 * first available slot's raw (unmasked) index. */
u32 quic_xskring_cons_peek(quic_xskring* r, u32 n, u32* idx);

/** Release n previously peeked slots back to the producer. */
void quic_xskring_cons_release(quic_xskring* r, u32 n);

/** Address slot accessor (fill/comp rings); idx is a raw (unmasked) index,
 * masked here. */
u64* quic_xskring_addr_at(quic_xskring* r, u32 idx);

/** Descriptor slot accessor (rx/tx rings); idx is a raw (unmasked) index,
 * masked here. */
quic_xdp_desc* quic_xskring_desc_at(quic_xskring* r, u32 idx);

#endif
