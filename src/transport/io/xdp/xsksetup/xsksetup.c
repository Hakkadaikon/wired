/* Syscall numbers not in the shared syscall.h table: this file is the only
 * user (naming-and-unity-build.md local-#define rule). Verified against
 * /usr/include/x86_64-linux-gnu/asm/unistd_64.h on this host (6.8.0):
 * __NR_getsockopt=55 (line 59). mmap/munmap moved to the shared table when
 * the thread runtime became a second user. */

/* AF_XDP / SOL_XDP (linux/bits/socket.h, x86_64-linux-gnu):
 * PF_XDP=44 (bits/socket.h:88, AF_XDP is an alias), SOL_XDP=283
 * (bits/socket.h:171). SOCK_RAW=3 is the standard Linux socket type value
 * (linux/net.h), used here per the plan's `socket(AF_XDP, SOCK_RAW, 0)`. */

/* setsockopt/getsockopt names (linux/if_xdp.h:74-80). */

/* mmap pgoff per ring (linux/if_xdp.h:109 onward): RX=0, TX=1<<31,
 * FILL=1<<32, COMPLETION=(1<<32)|(1<<31). */

/* mmap/mman constants (asm-generic/mman-common.h, bits/mman-linux.h):
 * PROT_READ=0x1, PROT_WRITE=0x2, MAP_SHARED=0x01, MAP_PRIVATE=0x02,
 * MAP_ANONYMOUS=0x20, MAP_POPULATE=0x8000. */

#include "transport/io/xdp/xsksetup/xsksetup_impl.h"

static i64  xsksetup_mmap(usz len, u64 pgoff, i64 fd);
static i64  xsksetup_munmap(void* addr, usz len);
static i64  xsksetup_ring_size(i64 fd, int name);
static usz  xsksetup_ring_len(const xsk_ring_offset* o, usz entry_size);
static void xsksetup_view(
    xskring_view* v, void* base, const xsk_ring_offset* o);
static i64 xsksetup_map_one(
    xsk*                   x,
    xskring*               ring,
    void**                 map,
    usz*                   map_len,
    u64                    pgoff,
    const xsk_ring_offset* o,
    usz                    entry_size);
static i64 xsksetup_map_fill_comp(xsk* x, const xsk_mmap_offsets* mo);
static i64 xsksetup_map_rx_tx(xsk* x, const xsk_mmap_offsets* mo);

static i64 xsksetup_mmap(usz len, u64 pgoff, i64 fd) {
  return wired_arch_mmap(
      0, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, pgoff);
}

static i64 xsksetup_munmap(void* addr, usz len) {
  if (!addr) {
    return 0;
  }
  return wired_arch_munmap((i64)addr, len);
}

/* Undo whatever of x was already built, in reverse order. Every field is
 * safe to unwind unconditionally: munmap/close ignore a NULL/-1 handle. */
void xsksetup_unwind(xsk* x) {
  xsksetup_munmap(x->map_comp, x->map_comp_len);
  xsksetup_munmap(x->map_fill, x->map_fill_len);
  xsksetup_munmap(x->map_tx, x->map_tx_len);
  xsksetup_munmap(x->map_rx, x->map_rx_len);
  if (x->umem) {
    xsksetup_munmap(x->umem, x->umem_len);
  }
  if (x->fd >= 0) {
    wired_arch_close(x->fd);
  }
  x->fd = -1;
}

/* Allocate the UMEM as one anonymous mmap and register it with the socket
 * via XDP_UMEM_REG. */
i64 xsksetup_umem(xsk* x) {
  i64          r;
  xsk_umem_reg reg = {0, XSKSETUP_UMEM_LEN, XSKSETUP_FRAME_SIZE, 0, 0, 0};
  r                = wired_arch_mmap(
      0, XSKSETUP_UMEM_LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
      -1, 0);
  if (r < 0) {
    return r;
  }
  x->umem     = (u8*)r;
  x->umem_len = XSKSETUP_UMEM_LEN;
  reg.addr    = (u64)x->umem;
  r = wired_arch_setsockopt(x->fd, SOL_XDP, XDP_UMEM_REG, &reg, sizeof reg);
  return r;
}

/* Set the entry count of all four rings via their respective setsockopts. */
static i64 xsksetup_ring_size(i64 fd, int name) {
  u32 n = XSKSETUP_RING_ENTRIES;
  return wired_arch_setsockopt(fd, SOL_XDP, name, &n, sizeof n);
}

i64 xsksetup_ring_sizes(xsk* x) {
  static const int names[4] = {
      XDP_UMEM_FILL_RING, XDP_UMEM_COMPLETION_RING, XDP_RX_RING, XDP_TX_RING};
  for (usz i = 0; i < 4; i++) {
    i64 r = xsksetup_ring_size(x->fd, names[i]);
    if (r < 0) {
      return r;
    }
  }
  return 0;
}

/* One ring's mmap length: the descriptor array's offset plus entries *
 * entry_size (entry_size is 16 for rx/tx's xdp_desc, 8 for the bare u64
 * addresses of fill/comp). */
static usz xsksetup_ring_len(const xsk_ring_offset* o, usz entry_size) {
  return (usz)o->desc + XSKSETUP_RING_ENTRIES * entry_size;
}

static void xsksetup_view(
    xskring_view* v, void* base, const xsk_ring_offset* o) {
  v->producer = (u32*)((u8*)base + o->producer);
  v->consumer = (u32*)((u8*)base + o->consumer);
  v->desc     = (u8*)base + o->desc;
  v->size     = XSKSETUP_RING_ENTRIES;
}

/* mmap one ring at the given pgoff/offsets-entry_size and init its
 * xskring from the resulting view. On failure returns the mmap's
 * negative errno without touching map/map_len (caller's xsksetup_unwind
 * still sees the prior NULL). */
static i64 xsksetup_map_one(
    xsk*                   x,
    xskring*               ring,
    void**                 map,
    usz*                   map_len,
    u64                    pgoff,
    const xsk_ring_offset* o,
    usz                    entry_size) {
  xskring_view v;
  usz          len = xsksetup_ring_len(o, entry_size);
  i64          r   = xsksetup_mmap(len, pgoff, x->fd);
  if (r < 0) {
    return r;
  }
  *map     = (void*)r;
  *map_len = len;
  xsksetup_view(&v, *map, o);
  xskring_init(ring, &v);
  return 0;
}

/* fill/comp share the 8-byte (bare u64 address) entry size. */
static i64 xsksetup_map_fill_comp(xsk* x, const xsk_mmap_offsets* mo) {
  i64 r = xsksetup_map_one(
      x, &x->fill, &x->map_fill, &x->map_fill_len, XDP_PGOFF_FILL_RING, &mo->fr,
      8);
  if (r < 0) {
    return r;
  }
  return xsksetup_map_one(
      x, &x->comp, &x->map_comp, &x->map_comp_len, XDP_PGOFF_COMPLETION_RING,
      &mo->cr, 8);
}

/* rx/tx share the 16-byte xdp_desc entry size. */
static i64 xsksetup_map_rx_tx(xsk* x, const xsk_mmap_offsets* mo) {
  i64 r = xsksetup_map_one(
      x, &x->rx, &x->map_rx, &x->map_rx_len, XDP_PGOFF_RX_RING, &mo->rx,
      sizeof(xdp_desc));
  if (r < 0) {
    return r;
  }
  return xsksetup_map_one(
      x, &x->tx, &x->map_tx, &x->map_tx_len, XDP_PGOFF_TX_RING, &mo->tx,
      sizeof(xdp_desc));
}

i64 xsksetup_map_rings(xsk* x, const xsk_mmap_offsets* mo) {
  i64 r = xsksetup_map_fill_comp(x, mo);
  if (r < 0) {
    return r;
  }
  return xsksetup_map_rx_tx(x, mo);
}
