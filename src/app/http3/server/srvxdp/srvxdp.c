#include "app/http3/server/srvxdp/srvxdp.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "transport/io/xdp/xdpbpf/xdpbpf.h"
#include "transport/io/xdp/xdpframe/xdpframe.h"

/** Number of frames in the TX pool (UMEM frames 64..127; the RX pool,
 * frames 0..63, belongs to the kernel's fill/rx rings). */
#define SRVXDP_TXPOOL_FRAMES 64u
/* Cast to u64 before multiplying (bugprone-implicit-widening-of-
 * multiplication-result): SRVXDP_TXPOOL_BASE is a UMEM byte offset, so the
 * product must be computed at that width, not implicitly widened from a
 * u32*u32 result after the fact. */
#define SRVXDP_TXPOOL_BASE ((u64)SRVXDP_TXPOOL_FRAMES * QUIC_XSKSETUP_FRAME_SIZE)

static u32 srvxdp_ip_be(const u8 ip[4]) {
  return ((u32)ip[0] << 24) | ((u32)ip[1] << 16) | ((u32)ip[2] << 8) |
         (u32)ip[3];
}

/* Close one fd unconditionally; a negative fd is simply not closed. */
static void srvxdp_close_fd(i64* fd) {
  if (*fd >= 0) syscall1(SYS_close, *fd);
  *fd = -1;
}

/* Undo whatever of x's BPF objects were already built, in reverse order. */
static void srvxdp_bpf_unwind(wired_srvxdp* x) {
  i64* fds[3] = {&x->link_fd, &x->prog_fd, &x->map_fd};
  for (usz i = 0; i < 3; i++) srvxdp_close_fd(fds[i]);
}

/* Create the XSKMAP and load the redirect-filter program built around it.
 * Returns 0, or the first negative errno. */
static i64 srvxdp_bpf_load(wired_srvxdp* x, const wired_srvxdp_cfg* cfg) {
  u64 insns[QUIC_XDPBPF_PROG_LEN];
  x->map_fd = quic_xdpbpf_map_create(SRVXDP_TXPOOL_FRAMES);
  if (x->map_fd < 0) return x->map_fd;
  quic_xdpbpf_prog_build(insns, (i32)x->map_fd, cfg->port);
  x->prog_fd =
      quic_xdpbpf_prog_load(insns, QUIC_XDPBPF_PROG_LEN, quic_mspan_of(0, 0));
  return x->prog_fd < 0 ? x->prog_fd : 0;
}

/* Attach the loaded program to the interface, then point the map's
 * queue_id slot at x->xsk.fd. Returns 0, or the first negative errno. */
static i64 srvxdp_bpf_attach(wired_srvxdp* x, const wired_srvxdp_cfg* cfg) {
  x->link_fd =
      quic_xdpbpf_link_create(x->prog_fd, cfg->ifindex, cfg->attach_flags);
  if (x->link_fd < 0) return x->link_fd;
  return quic_xdpbpf_map_set(x->map_fd, cfg->queue_id, (u32)x->xsk.fd);
}

/* Build, load and attach the redirect filter, then wire the map to
 * x->xsk.fd. Returns 0, or the first negative errno. */
static i64 srvxdp_bpf_build(wired_srvxdp* x, const wired_srvxdp_cfg* cfg) {
  i64 r = srvxdp_bpf_load(x, cfg);
  if (r < 0) return r;
  return srvxdp_bpf_attach(x, cfg);
}

/* Open the AF_XDP socket/rings; the step that needs no BPF objects yet. */
static i64 srvxdp_open_head(wired_srvxdp* x, const wired_srvxdp_cfg* cfg) {
  quic_xsk_cfg xc = {cfg->ifindex, cfg->queue_id, cfg->bind_flags};
  return quic_xsksetup_open(&x->xsk, &xc);
}

/* Build the BPF filter/map/link and wire the map to x->xsk.fd; the step
 * that needs x->xsk already open. */
static i64 srvxdp_open_body(wired_srvxdp* x, const wired_srvxdp_cfg* cfg) {
  return srvxdp_bpf_build(x, cfg);
}

i64 wired_srvxdp_open(wired_srvxdp* x, const wired_srvxdp_cfg* cfg) {
  i64 r;
  *x         = (wired_srvxdp){0};
  x->map_fd  = -1;
  x->prog_fd = -1;
  x->link_fd = -1;
  x->ip_be   = srvxdp_ip_be(cfg->ip);
  x->port    = cfg->port;
  quic_xdpmac_init(&x->macs);
  quic_xskumem_alloc_init(&x->txpool, SRVXDP_TXPOOL_BASE, SRVXDP_TXPOOL_FRAMES);

  r = srvxdp_open_head(x, cfg);
  if (r < 0) return r;
  r = srvxdp_open_body(x, cfg);
  if (r < 0) {
    srvxdp_bpf_unwind(x);
    quic_xsksetup_close(&x->xsk);
    return r;
  }
  return 0;
}

void wired_srvxdp_close(wired_srvxdp* x) {
  srvxdp_bpf_unwind(x);
  quic_xsksetup_close(&x->xsk);
}

/* Reap the completion ring: every finished TX frame address goes back to
 * txpool. Returns the number of frames reaped. */
static u32 srvxdp_reap_comp(wired_srvxdp* x) {
  u32 idx;
  u32 n = quic_xskring_cons_peek(&x->xsk.comp, x->xsk.comp.size, &idx);
  for (u32 i = 0; i < n; i++)
    quic_xskumem_alloc_put(
        &x->txpool, *quic_xskring_addr_at(&x->xsk.comp, idx + i));
  if (n) quic_xskring_cons_release(&x->xsk.comp, n);
  return n;
}

/* Learn the peer's MAC (and, the first time, our own) from one parsed RX
 * frame. */
static void srvxdp_learn(wired_srvxdp* x, const quic_xdpframe_rx* rx) {
  quic_xdpmac_learn(&x->macs, rx->src.addr_be, rx->peer_mac);
  if (!x->have_mac) {
    for (usz i = 0; i < 6; i++) x->our_mac[i] = rx->our_mac[i];
    x->have_mac = 1;
  }
}

/* Process one RX frame at umem offset addr/len: parse it, and on success
 * copy its payload/src into *out. Returns 1 if out was filled, 0 if the
 * frame was rejected (e.g. malformed) or too large for out->buf. */
static int srvxdp_rx_one(
    wired_srvxdp* x, u64 addr, u32 len, quic_mmsg_buf* out) {
  quic_xdpframe_rx rx;
  quic_span        frame = quic_span_of(x->xsk.umem + addr, len);
  if (!quic_xdpframe_parse(frame, &rx)) return 0;
  if (rx.payload_len > out->buf.n) return 0;
  srvxdp_learn(x, &rx);
  quic_memcpy(out->buf.p, rx.payload, rx.payload_len);
  out->len = (u32)rx.payload_len;
  out->src = rx.src;
  return 1;
}

/* Return nframes RX frame addresses (read via addr_at at rx_idx..) to the
 * fill ring, unconditionally (a full fill ring cannot happen: the RX pool
 * never has more frames in flight than the ring capacity). */
static void srvxdp_refill(wired_srvxdp* x, u32 rx_idx, u32 nframes) {
  u32 fill_idx;
  u32 got = quic_xskring_prod_reserve(&x->xsk.fill, nframes, &fill_idx);
  for (u32 i = 0; i < got; i++) {
    quic_xdp_desc* d = quic_xskring_desc_at(&x->xsk.rx, rx_idx + i);
    *quic_xskring_addr_at(&x->xsk.fill, fill_idx + i) = d->addr;
  }
  quic_xskring_prod_submit(&x->xsk.fill, got);
}

/* Process every peeked RX frame [rx_idx, rx_idx+n) into bufs, returning the
 * number of slots filled (<= n). */
static u32 srvxdp_rx_drain(
    wired_srvxdp* x, u32 rx_idx, u32 n, quic_mmsg_buf* bufs) {
  u32 filled = 0;
  for (u32 i = 0; i < n; i++) {
    quic_xdp_desc* d = quic_xskring_desc_at(&x->xsk.rx, rx_idx + i);
    if (srvxdp_rx_one(x, d->addr, d->len, &bufs[filled])) filled++;
  }
  return filled;
}

i64 wired_srvxdp_rx_burst(wired_srvxdp* x, quic_mmsg_buf* bufs, usz nbufs) {
  u32 rx_idx;
  u32 filled;
  u32 n;
  srvxdp_reap_comp(x);
  n      = quic_xskring_cons_peek(&x->xsk.rx, (u32)nbufs, &rx_idx);
  filled = srvxdp_rx_drain(x, rx_idx, n, bufs);
  if (!n) return filled;
  srvxdp_refill(x, rx_idx, n);
  quic_xskring_cons_release(&x->xsk.rx, n);
  return filled;
}

/* Get one TX frame from txpool, reaping completions once if the pool is
 * empty. Returns the frame address, or -1 if still empty. */
static i64 srvxdp_txpool_get(wired_srvxdp* x) {
  i64 addr = quic_xskumem_alloc_get(&x->txpool);
  if (addr >= 0) return addr;
  srvxdp_reap_comp(x);
  return quic_xskumem_alloc_get(&x->txpool);
}

/* Fill in m's addressing: peer_mac/our_mac plus the ports and addresses
 * quic_xdpframe_build needs, all in host order. */
static void srvxdp_tx_meta(
    wired_srvxdp*           x,
    const quic_sockaddr_in* dst,
    const u8                peer_mac[6],
    quic_xdpframe_tx*       m) {
  for (usz i = 0; i < 6; i++) m->dst_mac[i] = peer_mac[i];
  for (usz i = 0; i < 6; i++) m->src_mac[i] = x->our_mac[i];
  m->udp.ports.sport = x->port;
  m->udp.ports.dport = quic_get_be16((const u8*)&dst->port_be);
  m->udp.addrs.src   = quic_get_be32((const u8*)&x->ip_be);
  m->udp.addrs.dst   = quic_get_be32((const u8*)&dst->addr_be);
}

/* Submit one TX-pool frame (addr, n bytes already built) to the tx ring and
 * kick the kernel. Returns 1 sent, or 0 if the tx ring is full (the frame
 * is returned to txpool). */
static i64 srvxdp_tx_submit(wired_srvxdp* x, i64 addr, usz n) {
  u32            tx_idx;
  quic_xdp_desc* d;
  if (quic_xskring_prod_reserve(&x->xsk.tx, 1, &tx_idx) != 1) {
    quic_xskumem_alloc_put(&x->txpool, (u64)addr);
    return 0;
  }
  d          = quic_xskring_desc_at(&x->xsk.tx, tx_idx);
  d->addr    = (u64)addr;
  d->len     = (u32)n;
  d->options = 0;
  quic_xskring_prod_submit(&x->xsk.tx, 1);
  quic_xsksetup_kick_tx(x->xsk.fd);
  return 1;
}

i64 wired_srvxdp_send(
    wired_srvxdp* x, const quic_sockaddr_in* dst, quic_span pkt) {
  u8               peer_mac[6];
  quic_xdpframe_tx m;
  i64              addr;
  usz              n;

  if (!quic_xdpmac_lookup(&x->macs, dst->addr_be, peer_mac)) return 0;
  addr = srvxdp_txpool_get(x);
  if (addr < 0) return 0;

  srvxdp_tx_meta(x, dst, peer_mac, &m);
  n = quic_xdpframe_build(
      quic_mspan_of(x->xsk.umem + addr, QUIC_XSKSETUP_FRAME_SIZE), &m, pkt);
  return srvxdp_tx_submit(x, addr, n);
}
