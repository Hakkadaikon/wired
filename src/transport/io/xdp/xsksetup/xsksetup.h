#ifndef QUIC_XSKSETUP_XSKSETUP_H
#define QUIC_XSKSETUP_XSKSETUP_H

#include "common/platform/sys/syscall.h"
#include "transport/io/xdp/xskring/xskring.h"

/** @file
 * AF_XDP socket setup: socket(2)/setsockopt(2)/getsockopt(2)/mmap(2)/bind(2)
 * sequence that turns a raw AF_XDP fd into four ready-to-poll SPSC rings
 * (fill/comp/rx/tx) over one UMEM. Everything above this layer (ring
 * op / frame parse / bpf) is pure and already tested; this file is only the
 * syscall plumbing that wires those parts to the kernel. */

/** Fixed capacity: one UMEM frame per fill/comp/rx/tx ring entry slot count
 * below, matching xskumem's QUIC_XSKUMEM_FRAMES (128 frames of 2048B). */
#define QUIC_XSKSETUP_UMEM_FRAMES 128u
/** Byte size of one UMEM frame, matching xskumem's QUIC_XSKUMEM_FRAME_SIZE. */
#define QUIC_XSKSETUP_FRAME_SIZE 2048u
/** Total UMEM byte length. Cast to u64 before multiplying: both operands are
 * u32, and a plain u32*u32 product then gets implicitly widened when used as
 * a u64 length/offset (bugprone-implicit-widening-of-multiplication-result).
 * The current constants fit in 32 bits either way, but computing the product
 * in the target width is what the mmap length/UMEM offset math needs. */
#define QUIC_XSKSETUP_UMEM_LEN \
  ((u64)QUIC_XSKSETUP_UMEM_FRAMES * QUIC_XSKSETUP_FRAME_SIZE)

/** Entries per ring (fill/comp/rx/tx), must be a power of two. */
#define QUIC_XSKSETUP_RING_ENTRIES 64u

/** Caller-supplied configuration for one AF_XDP socket. */
typedef struct {
  /** network interface index */
  u32 ifindex;
  /** RX queue index to bind */
  u32 queue_id;
  /** XDP bind flags (0 = kernel default) */
  u16 bind_flags;
} quic_xsk_cfg;

/** One open AF_XDP socket: the fd, its UMEM, the four rings, and the mmap
 * regions backing them (kept so quic_xsksetup_close can munmap them). */
typedef struct {
  /** the AF_XDP socket fd, -1 once closed */
  i64 fd;
  /** UMEM base address */
  u8* umem;
  /** UMEM byte length */
  usz umem_len;

  /** RX ring (kernel -> app: received frames) */
  quic_xskring rx;
  /** TX ring (app -> kernel: frames to send) */
  quic_xskring tx;
  /** fill ring (app -> kernel: free RX frames) */
  quic_xskring fill;
  /** completion ring (kernel -> app: finished TX frames) */
  quic_xskring comp;

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
} quic_xsk;

/** Open one AF_XDP socket bound to cfg->ifindex/queue_id: socket -> UMEM
 * anonymous mmap -> XDP_UMEM_REG -> ring size setsockopts -> XDP_MMAP_OFFSETS
 * -> mmap the four rings -> quic_xskring_init each -> bind -> prime the fill
 * ring with all RX-pool frames. On any failure, everything allocated so far
 * is unwound and a negative errno is returned.
 * @param x   zero-initialized output; filled in on success
 * @param cfg ifindex/queue_id/bind_flags
 * @return 0 on success, or a negative errno */
i64 quic_xsksetup_open(quic_xsk* x, const quic_xsk_cfg* cfg);

/** Tear down x: munmap every ring region and the UMEM, close the fd. Safe to
 * call twice (a second call is a no-op: fd is left at -1 after the first). */
void quic_xsksetup_close(quic_xsk* x);

/** Wake the kernel to service the TX ring (sendto with no data, matching the
 * driver's XDP_COPY bind mode which needs an explicit kick). */
i64 quic_xsksetup_kick_tx(i64 fd);

/** Read XDP_STATISTICS into out[6]: rx_dropped, rx_invalid_descs,
 * tx_invalid_descs, rx_ring_full, rx_fill_ring_empty_descs,
 * tx_ring_empty_descs (linux/if_xdp.h struct xdp_statistics order). */
i64 quic_xsksetup_stats(i64 fd, u64 out[6]);

#endif
