/** Number of frames in the TX pool: every UMEM frame not reserved for RX
 * (frames XSKSETUP_RX_POOL_FRAMES..XSKSETUP_UMEM_FRAMES-1). The RX pool
 * (frames 0..XSKSETUP_RX_POOL_FRAMES-1) belongs to the kernel's fill/rx
 * rings. A 1MB HTTP/3 response body needs ~750 in-flight TX frames at the
 * ~1400B QUIC packet size; a too-small pool here is what made large
 * transfers hang (see xsksetup.h's XSKSETUP_UMEM_FRAMES comment). */
/* TX pool starts right after the RX pool's frames (0..RX_POOL_FRAMES-1).
 * Cast to u64 before multiplying (bugprone-implicit-widening-of-
 * multiplication-result): SRVXDP_TXPOOL_BASE is a UMEM byte offset, so the
 * product must be computed at that width, not implicitly widened from a
 * u32*u32 result after the fact. */

#include "app/http3/server/srvxdp/srvxdp_impl.h"

static void srvxdp_init_state(wired_srvxdp* x, const wired_srvxdp_cfg* cfg);
static i64  srvxdp_open_xsk(
    wired_srvxdp* x, const wired_srvxdp_cfg* cfg, wired_srvxdpbpf* bpf);

/* Initialize x's non-BPF state (identity, MAC cache, TX pool) from cfg. */
static void srvxdp_init_state(wired_srvxdp* x, const wired_srvxdp_cfg* cfg) {
  *x            = (wired_srvxdp){0};
  x->bpf.map_fd = x->bpf.prog_fd = x->bpf.link_fd = -1;
  /* ip_be holds the address as network-order BYTES, so tx_meta's
   * get_be32 round-trips it; a host-order u32 here byte-reverses the
   * reply's source IP on the wire. */
  bytes_memcpy((u8*)&x->ip_be, cfg->ip, 4);
  x->port = cfg->port;
  xdpmac_init(&x->macs);
  xskumem_alloc_init(&x->txpool, SRVXDP_TXPOOL_BASE, SRVXDP_TXPOOL_FRAMES);
}

/* Open the AF_XDP socket/rings and point bpf's queue_id map slot at the new
 * socket's fd, closing the socket again if the registration fails. Returns
 * 0, or the first negative errno. */
static i64 srvxdp_open_xsk(
    wired_srvxdp* x, const wired_srvxdp_cfg* cfg, wired_srvxdpbpf* bpf) {
  xsk_cfg xc = {cfg->ifindex, cfg->queue_id, cfg->bind_flags};
  i64     r  = xsksetup_open(&x->xsk, &xc);
  if (r < 0) return r;
  r = wired_srvxdpbpf_register(bpf, cfg->queue_id, (u32)x->xsk.fd);
  if (r < 0) xsksetup_close(&x->xsk);
  return r;
}

i64 wired_srvxdp_open(wired_srvxdp* x, const wired_srvxdp_cfg* cfg) {
  i64 r;
  srvxdp_init_state(x, cfg);
  r = wired_srvxdpbpf_open(&x->bpf, cfg->ifindex, cfg->port, cfg->attach_flags);
  if (r < 0) return r;
  x->bpf_owned = 1;
  r            = srvxdp_open_xsk(x, cfg, &x->bpf);
  if (r < 0) wired_srvxdpbpf_close(&x->bpf);
  return r;
}

i64 wired_srvxdp_open_shared(
    wired_srvxdp* x, const wired_srvxdp_cfg* cfg, wired_srvxdpbpf* bpf) {
  srvxdp_init_state(x, cfg);
  return srvxdp_open_xsk(x, cfg, bpf);
}

void wired_srvxdp_close(wired_srvxdp* x) {
  if (x->bpf_owned) wired_srvxdpbpf_close(&x->bpf);
  xsksetup_close(&x->xsk);
}
