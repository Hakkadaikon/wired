#ifndef QUIC_XSKUMEM_XSKUMEM_H
#define QUIC_XSKUMEM_XSKUMEM_H

#include "common/platform/sys/syscall.h"

/* Fixed-capacity UMEM frame allocator. Frames are identified by their
 * UMEM-relative offset (base_addr + i*QUIC_XSKUMEM_FRAME_SIZE) rather than a
 * pointer, since that offset is exactly what the kernel's fill/completion
 * rings carry. A LIFO free list is enough: ownership only ever moves between
 * "free" and "in flight", never needs ordering. */

/** Byte size of one UMEM frame. */
#define QUIC_XSKUMEM_FRAME_SIZE 2048u

/** Total number of frames this allocator manages. */
#define QUIC_XSKUMEM_FRAMES 128u

/** Fixed-capacity LIFO free list of UMEM frame addresses. */
typedef struct {
  u64 free[QUIC_XSKUMEM_FRAMES]; /**< free frame addresses (offsets into UMEM)
                                  */
  u32 nfree;                     /**< number of valid entries in free[] */
} quic_xskumem_alloc;

/** Push nframes frame addresses (base_addr + i*QUIC_XSKUMEM_FRAME_SIZE, for
 * i in [0, nframes)) onto the free list. nframes must be <=
 * QUIC_XSKUMEM_FRAMES; a caller-supplied excess is silently truncated to
 * QUIC_XSKUMEM_FRAMES.
 * @param a         allocator to initialize
 * @param base_addr UMEM base offset for frame 0
 * @param nframes   number of frames to seed the free list with */
void quic_xskumem_alloc_init(quic_xskumem_alloc* a, u64 base_addr, u32 nframes);

/** Pop one frame address from the free list.
 * @param a allocator
 * @return the frame address, or -1 if the free list is empty. */
i64 quic_xskumem_alloc_get(quic_xskumem_alloc* a);

/** Push a frame address back onto the free list. A no-op (defensive against a
 * double put) if the free list is already at capacity.
 * @param a    allocator
 * @param addr frame address to return */
void quic_xskumem_alloc_put(quic_xskumem_alloc* a, u64 addr);

#endif
