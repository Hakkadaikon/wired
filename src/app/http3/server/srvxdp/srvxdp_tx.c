#include "app/http3/server/srvxdp/srvxdp_impl.h"

static void srvxdp_tx_meta(
    wired_srvxdp* x, const sockaddr* dst, const u8 peer_mac[6], xdpframe_tx* m);
static i64  srvxdp_tx_submit(wired_srvxdp* x, i64 addr, usz n);
static void srvxdp_log_stat_line(const char* name, u64 v);

/* Fill in m's addressing: peer_mac/our_mac plus the ports and addresses
 * xdpframe_build needs, all in host order. */
static void srvxdp_tx_meta(
    wired_srvxdp*   x,
    const sockaddr* dst,
    const u8        peer_mac[6],
    xdpframe_tx*    m) {
  for (usz i = 0; i < 6; i++) {
    m->dst_mac[i] = peer_mac[i];
  }
  for (usz i = 0; i < 6; i++) {
    m->src_mac[i] = x->our_mac[i];
  }
  m->udp.ports.sport = x->port;
  m->udp.ports.dport = be_get_be16((const u8*)&dst->port_be);
  m->udp.addrs.src   = be_get_be32((const u8*)&x->ip_be);
  m->udp.addrs.dst   = wired_udp_addr4_be(dst);
}

/* Submit one TX-pool frame (addr, n bytes already built) to the tx ring and
 * kick the kernel. Returns 1 sent, or 0 if the tx ring is full (the frame
 * is returned to txpool). */
static i64 srvxdp_tx_submit(wired_srvxdp* x, i64 addr, usz n) {
  u32       tx_idx;
  xdp_desc* d;
  if (xskring_prod_reserve(&x->xsk.tx, 1, &tx_idx) != 1) {
    xskumem_alloc_put(&x->txpool, (u64)addr);
    return 0;
  }
  d          = xskring_desc_at(&x->xsk.tx, tx_idx);
  d->addr    = (u64)addr;
  d->len     = (u32)n;
  d->options = 0;
  xskring_prod_submit(&x->xsk.tx, 1);
  xsksetup_kick_tx(x->xsk.fd);
  return 1;
}

i64 wired_srvxdp_send(wired_srvxdp* x, const sockaddr* dst, wired_span pkt) {
  u8          peer_mac[6];
  xdpframe_tx m;
  i64         addr;
  usz         n;

  if (!xdpmac_lookup(&x->macs, wired_udp_addr4_be(dst), peer_mac)) {
    return 0;
  }
  addr = srvxdp_txpool_get(x);
  if (addr < 0) {
    return 0;
  }

  srvxdp_tx_meta(x, dst, peer_mac, &m);
  n = xdpframe_build(
      wired_mspan_of(x->xsk.umem + addr, XSKSETUP_FRAME_SIZE), &m, pkt);
  return srvxdp_tx_submit(x, addr, n);
}

/* Names for xsksetup_stats's out[6], in its documented order
 * (linux/if_xdp.h struct xdp_statistics field order). */
static const char* const SRVXDP_STAT_NAMES[6] = {
    "rx_dropped",   "rx_invalid_descs",         "tx_invalid_descs",
    "rx_ring_full", "rx_fill_ring_empty_descs", "tx_ring_empty_descs",
};

/* Format one "name value\n" line into line (caller-sized) and log it. */
static void srvxdp_log_stat_line(const char* name, u64 v) {
  char line[64];
  usz  at = 0;
  while (*name) {
    line[at++] = *name++;
  }
  line[at++] = ' ';
  wired_fmt_u64(line, &at, &(wired_fmt_u64_in){v, 1});
  line[at++] = '\n';
  line[at]   = 0;
  wired_log_str(line);
}

void wired_srvxdp_print_stats(i64 fd) {
  u64 stats[6];
  if (xsksetup_stats(fd, stats) < 0) {
    return;
  }
  for (usz i = 0; i < 6; i++) {
    srvxdp_log_stat_line(SRVXDP_STAT_NAMES[i], stats[i]);
  }
}
