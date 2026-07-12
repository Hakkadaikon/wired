#include "app/http3/server/srvxdp/srvxdp.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "common/platform/debug/debug.h"
#include "transport/io/xdp/xdpframe/xdpframe.h"

/** Number of frames in the TX pool (UMEM frames 64..127; the RX pool,
 * frames 0..63, belongs to the kernel's fill/rx rings). */
#define SRVXDP_TXPOOL_FRAMES 64u
/* Cast to u64 before multiplying (bugprone-implicit-widening-of-
 * multiplication-result): SRVXDP_TXPOOL_BASE is a UMEM byte offset, so the
 * product must be computed at that width, not implicitly widened from a
 * u32*u32 result after the fact. */
#define SRVXDP_TXPOOL_BASE \
  ((u64)SRVXDP_TXPOOL_FRAMES * QUIC_XSKSETUP_FRAME_SIZE)

/* Initialize x's non-BPF state (identity, MAC cache, TX pool) from cfg. */
static void srvxdp_init_state(wired_srvxdp* x, const wired_srvxdp_cfg* cfg) {
  *x            = (wired_srvxdp){0};
  x->bpf.map_fd = x->bpf.prog_fd = x->bpf.link_fd = -1;
  /* ip_be holds the address as network-order BYTES (same shape as
   * quic_sockaddr_in.addr_be), so tx_meta's get_be32 round-trips it; a
   * host-order u32 here byte-reverses the reply's source IP on the wire. */
  quic_memcpy((u8*)&x->ip_be, cfg->ip, 4);
  x->port = cfg->port;
  quic_xdpmac_init(&x->macs);
  quic_xskumem_alloc_init(&x->txpool, SRVXDP_TXPOOL_BASE, SRVXDP_TXPOOL_FRAMES);
}

/* Open the AF_XDP socket/rings and point bpf's queue_id map slot at the new
 * socket's fd, closing the socket again if the registration fails. Returns
 * 0, or the first negative errno. */
static i64 srvxdp_open_xsk(
    wired_srvxdp* x, const wired_srvxdp_cfg* cfg, wired_srvxdpbpf* bpf) {
  quic_xsk_cfg xc = {cfg->ifindex, cfg->queue_id, cfg->bind_flags};
  i64          r  = quic_xsksetup_open(&x->xsk, &xc);
  if (r < 0) return r;
  r = wired_srvxdpbpf_register(bpf, cfg->queue_id, (u32)x->xsk.fd);
  if (r < 0) quic_xsksetup_close(&x->xsk);
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

/* Names for quic_xsksetup_stats's out[6], in its documented order
 * (linux/if_xdp.h struct xdp_statistics field order). */
static const char* const SRVXDP_STAT_NAMES[6] = {
    "rx_dropped",   "rx_invalid_descs",         "tx_invalid_descs",
    "rx_ring_full", "rx_fill_ring_empty_descs", "tx_ring_empty_descs",
};

/* Format one "name value\n" line into line (caller-sized) and log it. */
static void srvxdp_log_stat_line(const char* name, u64 v) {
  char line[64];
  usz  at = 0;
  while (*name) line[at++] = *name++;
  line[at++] = ' ';
  wired_fmt_u64(line, &at, &(wired_fmt_u64_in){v, 1});
  line[at++] = '\n';
  line[at]   = 0;
  wired_log_str(line);
}

void wired_srvxdp_print_stats(i64 fd) {
  u64 stats[6];
  if (quic_xsksetup_stats(fd, stats) < 0) return;
  for (usz i = 0; i < 6; i++)
    srvxdp_log_stat_line(SRVXDP_STAT_NAMES[i], stats[i]);
}
