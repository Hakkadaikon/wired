#include "transport/io/xdp/xsksetup/xsksetup_impl.h"

static i64  xsksetup_get_offsets(i64 fd, xsk_mmap_offsets* mo);
static i64  xsksetup_bind(xsk* x, const xsk_cfg* cfg);
static void xsksetup_prime_fill(xsk* x);
static i64  xsksetup_build_head(xsk* x);
static i64  xsksetup_build_body(xsk* x, const xsk_cfg* cfg);
static i64  xsksetup_build(xsk* x, const xsk_cfg* cfg);

static i64 xsksetup_get_offsets(i64 fd, xsk_mmap_offsets* mo) {
  u32 len = sizeof(*mo);
  return wired_arch_getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, mo, &len);
}

static i64 xsksetup_bind(xsk* x, const xsk_cfg* cfg) {
  xsk_sockaddr sa = {AF_XDP, cfg->bind_flags, cfg->ifindex, cfg->queue_id, 0};
  return wired_arch_bind(x->fd, &sa, sizeof sa);
}

/* Push every RX-pool frame address (0..XSKSETUP_RX_POOL_FRAMES, matching
 * srvxdp's RX/TX pool split) onto the fill ring so the kernel has frames to
 * receive into as soon as bind completes. */
static void xsksetup_prime_fill(xsk* x) {
  u32 n   = XSKSETUP_RX_POOL_FRAMES;
  u32 idx = 0;
  u32 got = xskring_prod_reserve(&x->fill, n, &idx);
  for (u32 i = 0; i < got; i++)
    *xskring_addr_at(&x->fill, idx + i) = (u64)i * XSKSETUP_FRAME_SIZE;
  xskring_prod_submit(&x->fill, got);
}

/* UMEM registration and ring-size setsockopts: the two steps that need no
 * mmap'd ring data yet. */
static i64 xsksetup_build_head(xsk* x) {
  i64 r = xsksetup_umem(x);
  if (r < 0) return r;
  return xsksetup_ring_sizes(x);
}

/* Offsets + ring mmaps + bind: the steps that need x->fd already configured
 * by xsksetup_build_head. */
static i64 xsksetup_build_body(xsk* x, const xsk_cfg* cfg) {
  xsk_mmap_offsets mo;
  i64              r = xsksetup_get_offsets(x->fd, &mo);
  if (r < 0) return r;
  r = xsksetup_map_rings(x, &mo);
  if (r < 0) return r;
  return xsksetup_bind(x, cfg);
}

/* Runs the four-step open sequence, returning the negative errno of the
 * first step that fails. Split out of xsksetup_open so that function
 * stays a single CCN-1 dispatch. */
static i64 xsksetup_build(xsk* x, const xsk_cfg* cfg) {
  i64 r = xsksetup_build_head(x);
  if (r < 0) return r;
  return xsksetup_build_body(x, cfg);
}

i64 xsksetup_open(xsk* x, const xsk_cfg* cfg) {
  i64 r;
  *x    = (xsk){0};
  x->fd = wired_arch_socket(AF_XDP, SOCK_RAW, 0);
  if (x->fd < 0) return x->fd;
  r = xsksetup_build(x, cfg);
  if (r < 0) {
    xsksetup_unwind(x);
    return r;
  }
  xsksetup_prime_fill(x);
  return 0;
}

void xsksetup_close(xsk* x) {
  if (x->fd < 0) return;
  xsksetup_unwind(x);
}

i64 xsksetup_kick_tx(i64 fd) {
  return wired_arch_sendto(fd, 0, 0, 0x40 /* MSG_DONTWAIT */, 0, 0);
}

i64 xsksetup_stats(i64 fd, u64 out[6]) {
  u32 len = 6 * sizeof(u64);
  return wired_arch_getsockopt(fd, SOL_XDP, XDP_STATISTICS, out, &len);
}
