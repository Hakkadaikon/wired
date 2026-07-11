#include "transport/io/xdp/xsksetup/xsksetup.h"

/* Syscall numbers not in the shared syscall.h table: this file is the only
 * user (naming-and-unity-build.md local-#define rule). Verified against
 * /usr/include/x86_64-linux-gnu/asm/unistd_64.h on this host (6.8.0):
 * __NR_getsockopt=55 (line 59). mmap/munmap moved to the shared table when
 * the thread runtime became a second user. */
#define SYS_getsockopt 55

/* AF_XDP / SOL_XDP (linux/bits/socket.h, x86_64-linux-gnu):
 * PF_XDP=44 (bits/socket.h:88, AF_XDP is an alias), SOL_XDP=283
 * (bits/socket.h:171). SOCK_RAW=3 is the standard Linux socket type value
 * (linux/net.h), used here per the plan's `socket(AF_XDP, SOCK_RAW, 0)`. */
#define QUIC_AF_XDP 44
#define QUIC_SOCK_RAW 3
#define QUIC_SOL_XDP 283

/* setsockopt/getsockopt names (linux/if_xdp.h:74-80). */
#define QUIC_XDP_MMAP_OFFSETS 1
#define QUIC_XDP_RX_RING 2
#define QUIC_XDP_TX_RING 3
#define QUIC_XDP_UMEM_REG 4
#define QUIC_XDP_UMEM_FILL_RING 5
#define QUIC_XDP_UMEM_COMPLETION_RING 6
#define QUIC_XDP_STATISTICS 7

/* mmap pgoff per ring (linux/if_xdp.h:109 onward): RX=0, TX=1<<31,
 * FILL=1<<32, COMPLETION=(1<<32)|(1<<31). */
#define QUIC_XDP_PGOFF_RX_RING 0ULL
#define QUIC_XDP_PGOFF_TX_RING 0x80000000ULL
#define QUIC_XDP_PGOFF_FILL_RING 0x100000000ULL
#define QUIC_XDP_PGOFF_COMPLETION_RING 0x180000000ULL

/* mmap/mman constants (asm-generic/mman-common.h, bits/mman-linux.h):
 * PROT_READ=0x1, PROT_WRITE=0x2, MAP_SHARED=0x01, MAP_PRIVATE=0x02,
 * MAP_ANONYMOUS=0x20, MAP_POPULATE=0x8000. */
#define QUIC_PROT_READ 0x1
#define QUIC_PROT_WRITE 0x2
#define QUIC_MAP_SHARED 0x01
#define QUIC_MAP_PRIVATE 0x02
#define QUIC_MAP_ANONYMOUS 0x20
#define QUIC_MAP_POPULATE 0x8000

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

static i64 xsksetup_mmap(usz len, u64 pgoff, i64 fd) {
  return syscall6(
      SYS_mmap, 0, (i64)len, QUIC_PROT_READ | QUIC_PROT_WRITE,
      QUIC_MAP_SHARED | QUIC_MAP_POPULATE, fd, (i64)pgoff);
}

static i64 xsksetup_munmap(void* addr, usz len) {
  if (!addr) return 0;
  return syscall3(SYS_munmap, addr, len, 0);
}

/* Undo whatever of x was already built, in reverse order. Every field is
 * safe to unwind unconditionally: munmap/close ignore a NULL/-1 handle. */
static void xsksetup_unwind(quic_xsk* x) {
  xsksetup_munmap(x->map_comp, x->map_comp_len);
  xsksetup_munmap(x->map_fill, x->map_fill_len);
  xsksetup_munmap(x->map_tx, x->map_tx_len);
  xsksetup_munmap(x->map_rx, x->map_rx_len);
  if (x->umem) xsksetup_munmap(x->umem, x->umem_len);
  if (x->fd >= 0) syscall1(SYS_close, x->fd);
  x->fd = -1;
}

/* Allocate the UMEM as one anonymous mmap and register it with the socket
 * via XDP_UMEM_REG. */
static i64 xsksetup_umem(quic_xsk* x) {
  i64          r;
  xsk_umem_reg reg = {0, QUIC_XSKSETUP_UMEM_LEN, QUIC_XSKSETUP_FRAME_SIZE, 0, 0,
                      0};
  r                = syscall6(
      SYS_mmap, 0, QUIC_XSKSETUP_UMEM_LEN, QUIC_PROT_READ | QUIC_PROT_WRITE,
      QUIC_MAP_PRIVATE | QUIC_MAP_ANONYMOUS, -1, 0);
  if (r < 0) return r;
  x->umem     = (u8*)r;
  x->umem_len = QUIC_XSKSETUP_UMEM_LEN;
  reg.addr    = (u64)x->umem;
  r           = syscall6(
      SYS_setsockopt, x->fd, QUIC_SOL_XDP, QUIC_XDP_UMEM_REG, (i64)&reg,
      sizeof reg, 0);
  return r;
}

/* Set the entry count of all four rings via their respective setsockopts. */
static i64 xsksetup_ring_size(i64 fd, int name) {
  u32 n = QUIC_XSKSETUP_RING_ENTRIES;
  return syscall6(SYS_setsockopt, fd, QUIC_SOL_XDP, name, (i64)&n, sizeof n, 0);
}

static i64 xsksetup_ring_sizes(quic_xsk* x) {
  static const int names[4] = {
      QUIC_XDP_UMEM_FILL_RING, QUIC_XDP_UMEM_COMPLETION_RING, QUIC_XDP_RX_RING,
      QUIC_XDP_TX_RING};
  for (usz i = 0; i < 4; i++) {
    i64 r = xsksetup_ring_size(x->fd, names[i]);
    if (r < 0) return r;
  }
  return 0;
}

/* One ring's mmap length: the descriptor array's offset plus entries *
 * entry_size (entry_size is 16 for rx/tx's quic_xdp_desc, 8 for the bare u64
 * addresses of fill/comp). */
static usz xsksetup_ring_len(const xsk_ring_offset* o, usz entry_size) {
  return (usz)o->desc + QUIC_XSKSETUP_RING_ENTRIES * entry_size;
}

static void xsksetup_view(
    quic_xskring_view* v, void* base, const xsk_ring_offset* o) {
  v->producer = (u32*)((u8*)base + o->producer);
  v->consumer = (u32*)((u8*)base + o->consumer);
  v->desc     = (u8*)base + o->desc;
  v->size     = QUIC_XSKSETUP_RING_ENTRIES;
}

/* mmap one ring at the given pgoff/offsets-entry_size and init its
 * quic_xskring from the resulting view. On failure returns the mmap's
 * negative errno without touching map/map_len (caller's xsksetup_unwind
 * still sees the prior NULL). */
static i64 xsksetup_map_one(
    quic_xsk*              x,
    quic_xskring*          ring,
    void**                 map,
    usz*                   map_len,
    u64                    pgoff,
    const xsk_ring_offset* o,
    usz                    entry_size) {
  quic_xskring_view v;
  usz               len = xsksetup_ring_len(o, entry_size);
  i64               r   = xsksetup_mmap(len, pgoff, x->fd);
  if (r < 0) return r;
  *map     = (void*)r;
  *map_len = len;
  xsksetup_view(&v, *map, o);
  quic_xskring_init(ring, &v);
  return 0;
}

/* fill/comp share the 8-byte (bare u64 address) entry size. */
static i64 xsksetup_map_fill_comp(quic_xsk* x, const xsk_mmap_offsets* mo) {
  i64 r = xsksetup_map_one(
      x, &x->fill, &x->map_fill, &x->map_fill_len, QUIC_XDP_PGOFF_FILL_RING,
      &mo->fr, 8);
  if (r < 0) return r;
  return xsksetup_map_one(
      x, &x->comp, &x->map_comp, &x->map_comp_len,
      QUIC_XDP_PGOFF_COMPLETION_RING, &mo->cr, 8);
}

/* rx/tx share the 16-byte quic_xdp_desc entry size. */
static i64 xsksetup_map_rx_tx(quic_xsk* x, const xsk_mmap_offsets* mo) {
  i64 r = xsksetup_map_one(
      x, &x->rx, &x->map_rx, &x->map_rx_len, QUIC_XDP_PGOFF_RX_RING, &mo->rx,
      sizeof(quic_xdp_desc));
  if (r < 0) return r;
  return xsksetup_map_one(
      x, &x->tx, &x->map_tx, &x->map_tx_len, QUIC_XDP_PGOFF_TX_RING, &mo->tx,
      sizeof(quic_xdp_desc));
}

static i64 xsksetup_map_rings(quic_xsk* x, const xsk_mmap_offsets* mo) {
  i64 r = xsksetup_map_fill_comp(x, mo);
  if (r < 0) return r;
  return xsksetup_map_rx_tx(x, mo);
}

static i64 xsksetup_get_offsets(i64 fd, xsk_mmap_offsets* mo) {
  u32 len = sizeof(*mo);
  return syscall6(
      SYS_getsockopt, fd, QUIC_SOL_XDP, QUIC_XDP_MMAP_OFFSETS, (i64)mo,
      (i64)&len, 0);
}

static i64 xsksetup_bind(quic_xsk* x, const quic_xsk_cfg* cfg) {
  xsk_sockaddr sa = {
      QUIC_AF_XDP, cfg->bind_flags, cfg->ifindex, cfg->queue_id, 0};
  return syscall3(SYS_bind, x->fd, &sa, sizeof sa);
}

/* Push every RX-pool frame address (0..QUIC_XSKSETUP_UMEM_FRAMES/2, matching
 * xskumem's RX/TX pool split) onto the fill ring so the kernel has frames to
 * receive into as soon as bind completes. */
static void xsksetup_prime_fill(quic_xsk* x) {
  u32 n   = QUIC_XSKSETUP_UMEM_FRAMES / 2;
  u32 idx = 0;
  u32 got = quic_xskring_prod_reserve(&x->fill, n, &idx);
  for (u32 i = 0; i < got; i++)
    *quic_xskring_addr_at(&x->fill, idx + i) =
        (u64)i * QUIC_XSKSETUP_FRAME_SIZE;
  quic_xskring_prod_submit(&x->fill, got);
}

/* UMEM registration and ring-size setsockopts: the two steps that need no
 * mmap'd ring data yet. */
static i64 xsksetup_build_head(quic_xsk* x) {
  i64 r = xsksetup_umem(x);
  if (r < 0) return r;
  return xsksetup_ring_sizes(x);
}

/* Offsets + ring mmaps + bind: the steps that need x->fd already configured
 * by xsksetup_build_head. */
static i64 xsksetup_build_body(quic_xsk* x, const quic_xsk_cfg* cfg) {
  xsk_mmap_offsets mo;
  i64              r = xsksetup_get_offsets(x->fd, &mo);
  if (r < 0) return r;
  r = xsksetup_map_rings(x, &mo);
  if (r < 0) return r;
  return xsksetup_bind(x, cfg);
}

/* Runs the four-step open sequence, returning the negative errno of the
 * first step that fails. Split out of quic_xsksetup_open so that function
 * stays a single CCN-1 dispatch. */
static i64 xsksetup_build(quic_xsk* x, const quic_xsk_cfg* cfg) {
  i64 r = xsksetup_build_head(x);
  if (r < 0) return r;
  return xsksetup_build_body(x, cfg);
}

i64 quic_xsksetup_open(quic_xsk* x, const quic_xsk_cfg* cfg) {
  i64 r;
  *x    = (quic_xsk){0};
  x->fd = syscall3(SYS_socket, QUIC_AF_XDP, QUIC_SOCK_RAW, 0);
  if (x->fd < 0) return x->fd;
  r = xsksetup_build(x, cfg);
  if (r < 0) {
    xsksetup_unwind(x);
    return r;
  }
  xsksetup_prime_fill(x);
  return 0;
}

void quic_xsksetup_close(quic_xsk* x) {
  if (x->fd < 0) return;
  xsksetup_unwind(x);
}

i64 quic_xsksetup_kick_tx(i64 fd) {
  return syscall6(SYS_sendto, fd, 0, 0, 0x40 /* MSG_DONTWAIT */, 0, 0);
}

i64 quic_xsksetup_stats(i64 fd, u64 out[6]) {
  u32 len = 6 * sizeof(u64);
  return syscall6(
      SYS_getsockopt, fd, QUIC_SOL_XDP, QUIC_XDP_STATISTICS, (i64)out,
      (i64)&len, 0);
}
