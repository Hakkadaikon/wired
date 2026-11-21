#include "app/http3/server/srvxdp/srvxdp_impl.h"

static u32  srvxdp_reap_comp(wired_srvxdp* x);
static void srvxdp_learn(wired_srvxdp* x, const xdpframe_rx* rx);
static int  srvxdp_rx_one(wired_srvxdp* x, u64 addr, u32 len, mmsg_buf* out);
static void srvxdp_refill(wired_srvxdp* x, u32 rx_idx, u32 nframes);
static u32  srvxdp_rx_drain(wired_srvxdp* x, u32 rx_idx, u32 n, mmsg_buf* bufs);

/* Reap the completion ring: every finished TX frame address goes back to
 * txpool. Returns the number of frames reaped. */
static u32 srvxdp_reap_comp(wired_srvxdp* x) {
  u32 idx;
  u32 n = xskring_cons_peek(&x->xsk.comp, x->xsk.comp.size, &idx);
  for (u32 i = 0; i < n; i++) {
    xskumem_alloc_put(&x->txpool, *xskring_addr_at(&x->xsk.comp, idx + i));
  }
  if (n) {
    xskring_cons_release(&x->xsk.comp, n);
  }
  return n;
}

/* Learn the peer's MAC and the address it sent to (and, the first time,
 * our own MAC) from one parsed RX frame. */
static void srvxdp_learn(wired_srvxdp* x, const xdpframe_rx* rx) {
  xdpmac_learn(&x->macs, rx->src.addr, rx->peer_mac, rx->our_ip);
  if (!x->have_mac) {
    for (usz i = 0; i < 6; i++) {
      x->our_mac[i] = rx->our_mac[i];
    }
    x->have_mac = 1;
  }
}

/* Copy one parsed datagram's payload/src into *out and learn its
 * addressing. Returns 1 if out was filled, 0 if it is too large for
 * out->buf. */
int srvxdp_rx_deliver(wired_srvxdp* x, const xdpframe_rx* rx, mmsg_buf* out) {
  if (rx->payload_len > out->buf.n) {
    return 0;
  }
  srvxdp_learn(x, rx);
  bytes_memcpy(out->buf.p, rx->payload, rx->payload_len);
  out->len = (u32)rx->payload_len;
  out->src = rx->src;
  return 1;
}

/* Process one RX frame at umem offset addr/len: parse it, hand it to the
 * worker owning its connection (srvxdp_fwd.c), or deliver it into *out.
 * Returns 1 if out was filled, 0 if the frame was rejected (e.g.
 * malformed), forwarded, or too large for out->buf. */
static int srvxdp_rx_one(wired_srvxdp* x, u64 addr, u32 len, mmsg_buf* out) {
  xdpframe_rx rx;
  wired_span  frame = wired_span_of(x->xsk.umem + addr, len);
  u32         flags = (u32)(x->skip_udp_csum != 0) * XDPFRAME_SKIP_UDP_CSUM;
  if (!xdpframe_parse(frame, flags, &rx)) {
    return 0;
  }
  if (srvxdp_fwd_handoff(x, &rx)) {
    return 0;
  }
  return srvxdp_rx_deliver(x, &rx, out);
}

/* Return nframes RX frame addresses (read via addr_at at rx_idx..) to the
 * fill ring, unconditionally (a full fill ring cannot happen: the RX pool
 * never has more frames in flight than the ring capacity). */
static void srvxdp_refill(wired_srvxdp* x, u32 rx_idx, u32 nframes) {
  u32 fill_idx;
  u32 got = xskring_prod_reserve(&x->xsk.fill, nframes, &fill_idx);
  for (u32 i = 0; i < got; i++) {
    xdp_desc* d = xskring_desc_at(&x->xsk.rx, rx_idx + i);
    *xskring_addr_at(&x->xsk.fill, fill_idx + i) = d->addr;
  }
  xskring_prod_submit(&x->xsk.fill, got);
}

/* Process every peeked RX frame [rx_idx, rx_idx+n) into bufs, returning the
 * number of slots filled (<= n). */
static u32 srvxdp_rx_drain(wired_srvxdp* x, u32 rx_idx, u32 n, mmsg_buf* bufs) {
  u32 filled = 0;
  for (u32 i = 0; i < n; i++) {
    xdp_desc* d = xskring_desc_at(&x->xsk.rx, rx_idx + i);
    if (srvxdp_rx_one(x, d->addr, d->len, &bufs[filled])) {
      filled++;
    }
  }
  return filled;
}

/* Datagrams other workers forwarded here take at most half the batch
 * (rounded up). With nbufs >= 2 neither they nor this queue's own traffic
 * can starve the other; with nbufs == 1 a steady forwarded stream takes
 * every burst (srvrun always passes SRVRUN_RX_BATCH, 16). */
i64 wired_srvxdp_rx_burst(wired_srvxdp* x, mmsg_buf* bufs, usz nbufs) {
  u32 rx_idx;
  u32 fwd = srvxdp_fwd_drain(x, bufs, (u32)(nbufs + 1) / 2);
  u32 filled;
  u32 n;
  srvxdp_reap_comp(x);
  n      = xskring_cons_peek(&x->xsk.rx, (u32)nbufs - fwd, &rx_idx);
  filled = fwd + srvxdp_rx_drain(x, rx_idx, n, bufs + fwd);
  if (!n) {
    return filled;
  }
  srvxdp_refill(x, rx_idx, n);
  xskring_cons_release(&x->xsk.rx, n);
  return filled;
}

/* Get one TX frame from txpool, reaping completions once if the pool is
 * empty. Returns the frame address, or -1 if still empty. */
i64 srvxdp_txpool_get(wired_srvxdp* x) {
  i64 addr = xskumem_alloc_get(&x->txpool);
  if (addr >= 0) {
    return addr;
  }
  srvxdp_reap_comp(x);
  return xskumem_alloc_get(&x->txpool);
}
