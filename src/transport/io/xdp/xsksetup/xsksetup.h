#ifndef XSKSETUP_XSKSETUP_H
#define XSKSETUP_XSKSETUP_H

#include "common/platform/sys/syscall.h"
#include "transport/io/xdp/xskring/xskring.h"

/** @file
 * AF_XDP socket setup: socket(2)/setsockopt(2)/getsockopt(2)/mmap(2)/bind(2)
 * sequence that turns a raw AF_XDP fd into four ready-to-poll SPSC rings
 * (fill/comp/rx/tx) over one UMEM. Everything above this layer (ring
 * op / frame parse / bpf) is pure and already tested; this file is only the
 * syscall plumbing that wires those parts to the kernel. */

/** Fixed capacity: one UMEM frame per fill/comp/rx/tx ring entry slot count
 * below, matching xskumem's XSKUMEM_FRAMES (1024 frames of 2048B = 2MiB).
 * A 1MB file at a ~1400B QUIC packet size needs ~750 in-flight TX frames;
 * the prior 128-frame UMEM (64 TX) stalled on txpool exhaustion well before
 * that (observed as xdp_statistics.tx_ring_empty_descs = 14352 on a real
 * VPS run). 1024 gives headroom above that without growing the mmap past a
 * few MiB. */
#define XSKSETUP_UMEM_FRAMES 1024u
/** Byte size of one UMEM frame, matching xskumem's XSKUMEM_FRAME_SIZE. */
#define XSKSETUP_FRAME_SIZE 2048u
/** Total UMEM byte length. Cast to u64 before multiplying: both operands are
 * u32, and a plain u32*u32 product then gets implicitly widened when used as
 * a u64 length/offset (bugprone-implicit-widening-of-multiplication-result).
 * The current constants fit in 32 bits either way, but computing the product
 * in the target width is what the mmap length/UMEM offset math needs. */
#define XSKSETUP_UMEM_LEN ((u64)XSKSETUP_UMEM_FRAMES * XSKSETUP_FRAME_SIZE)

/** Number of UMEM frames (0..XSKSETUP_RX_POOL_FRAMES) reserved for the
 * kernel's fill/RX side (xsksetup_prime_fill). The remainder
 * (XSKSETUP_UMEM_FRAMES - XSKSETUP_RX_POOL_FRAMES) is the server's TX pool
 * (srvxdp's SRVXDP_TXPOOL_FRAMES). Skewed toward TX: an HTTP/3 server
 * mostly transmits (response bodies) and rarely needs many RX frames in
 * flight at once. */
#define XSKSETUP_RX_POOL_FRAMES 256u

/** Entries per ring (fill/comp/rx/tx), must be a power of two. */
#define XSKSETUP_RING_ENTRIES 64u

/** Caller-supplied configuration for one AF_XDP socket. */
typedef struct {
  /** network interface index */
  u32 ifindex;
  /** RX queue index to bind */
  u32 queue_id;
  /** XDP bind flags (0 = kernel default) */
  u16 bind_flags;
} xsk_cfg;

/** One open AF_XDP socket: the fd, its UMEM, the four rings, and the mmap
 * regions backing them (kept so xsksetup_close can munmap them). */
typedef struct {
  /** the AF_XDP socket fd, -1 once closed */
  i64 fd;
  /** UMEM base address */
  u8* umem;
  /** UMEM byte length */
  usz umem_len;

  /** RX ring (kernel -> app: received frames) */
  xskring rx;
  /** TX ring (app -> kernel: frames to send) */
  xskring tx;
  /** fill ring (app -> kernel: free RX frames) */
  xskring fill;
  /** completion ring (kernel -> app: finished TX frames) */
  xskring comp;

  /** mmap region backing the rx ring */
  void* map_rx;
  /** byte length of map_rx */
  usz map_rx_len;
  /** mmap region backing the tx ring */
  void* map_tx;
  /** byte length of map_tx */
  usz map_tx_len;
  /** mmap region backing the fill ring */
  void* map_fill;
  /** byte length of map_fill */
  usz map_fill_len;
  /** mmap region backing the comp ring */
  void* map_comp;
  /** byte length of map_comp */
  usz map_comp_len;
} xsk;

/** Open one AF_XDP socket bound to cfg->ifindex/queue_id: socket -> UMEM
 * anonymous mmap -> XDP_UMEM_REG -> ring size setsockopts -> XDP_MMAP_OFFSETS
 * -> mmap the four rings -> xskring_init each -> bind -> prime the fill
 * ring with all RX-pool frames. On any failure, everything allocated so far
 * is unwound and a negative errno is returned.
 * @param x   zero-initialized output; filled in on success
 * @param cfg ifindex/queue_id/bind_flags
 * @return 0 on success, or a negative errno */
i64 xsksetup_open(xsk* x, const xsk_cfg* cfg);

/** Tear down x: munmap every ring region and the UMEM, close the fd. Safe to
 * call twice (a second call is a no-op: fd is left at -1 after the first). */
void xsksetup_close(xsk* x);

/** Wake the kernel to service the TX ring (sendto with no data, matching the
 * driver's XDP_COPY bind mode which needs an explicit kick). */
i64 xsksetup_kick_tx(i64 fd);

/** Read XDP_STATISTICS into out[6]: rx_dropped, rx_invalid_descs,
 * tx_invalid_descs, rx_ring_full, rx_fill_ring_empty_descs,
 * tx_ring_empty_descs (linux/if_xdp.h struct xdp_statistics order). */
i64 xsksetup_stats(i64 fd, u64 out[6]);

#endif
