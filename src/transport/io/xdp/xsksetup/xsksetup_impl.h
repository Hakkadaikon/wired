#ifndef TRANSPORT_IO_XDP_XSKSETUP_XSKSETUP_IMPL_H
#define TRANSPORT_IO_XDP_XSKSETUP_XSKSETUP_IMPL_H

/* Internal to the xsksetup*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "transport/io/xdp/xsksetup/xsksetup.h"

#define AF_XDP 44
#define SOCK_RAW 3
#define SOL_XDP 283
#define XDP_MMAP_OFFSETS 1
#define XDP_RX_RING 2
#define XDP_TX_RING 3
#define XDP_UMEM_REG 4
#define XDP_UMEM_FILL_RING 5
#define XDP_UMEM_COMPLETION_RING 6
#define XDP_STATISTICS 7
#define XDP_PGOFF_RX_RING 0ULL
#define XDP_PGOFF_TX_RING 0x80000000ULL
#define XDP_PGOFF_FILL_RING 0x100000000ULL
#define XDP_PGOFF_COMPLETION_RING 0x180000000ULL
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define MAP_POPULATE 0x8000

/* struct sockaddr_xdp (linux/if_xdp.h:48-54), 16 bytes: family/flags are u16,
 * ifindex/queue_id/shared_umem_fd are u32. */
typedef struct {
  u16 family;
  u16 flags;
  u32 ifindex;
  u32 queue_id;
  u32 shared_umem_fd;
} xsk_sockaddr;

/* struct xdp_ring_offset (linux/if_xdp.h:59-64), 32 bytes: four u64 byte
 * offsets (from the mmap base) of the producer index, consumer index, the
 * descriptor array, and a flags word. */
typedef struct {
  u64 producer;
  u64 consumer;
  u64 desc;
  u64 flags;
} xsk_ring_offset;

/* struct xdp_mmap_offsets (linux/if_xdp.h:66-71), 128 bytes: one
 * xsk_ring_offset per ring, in rx/tx/fill/comp order. */
typedef struct {
  xsk_ring_offset rx, tx, fr, cr;
} xsk_mmap_offsets;

/* struct xdp_umem_reg (linux/if_xdp.h:83-90), 32 bytes. */
typedef struct {
  u64 addr;
  u64 len;
  u32 chunk_size;
  u32 headroom;
  u32 flags;
  u32 tx_metadata_len;
} xsk_umem_reg;

void xsksetup_unwind(xsk* x);
i64  xsksetup_umem(xsk* x);
i64  xsksetup_ring_sizes(xsk* x);
i64  xsksetup_map_rings(xsk* x, const xsk_mmap_offsets* mo);

#endif
