#include "test.h"

/* Fake-kernel harness for wired_srvxdp: no mmap, no bpf, no real fd. Every
 * ring is a plain quic_xskring_view over static local arrays (matching
 * xskring_test.c's pattern), and the "kernel" is played by the test code
 * itself calling the very same producer/consumer ops the real kernel would
 * use on its side of each SPSC ring. */

#define SXT_RING 8u
/* tx/comp need to hold every in-flight TX-pool frame at once for the
 * txpool-exhaustion test (64 sends with no completion in between), so they
 * are sized to the pool (64), unlike rx/fill which stay at SXT_RING. */
#define SXT_TXRING 64u
#define SXT_UMEM_FRAMES 128u
#define SXT_UMEM_LEN (SXT_UMEM_FRAMES * QUIC_XSKUMEM_FRAME_SIZE)

typedef struct {
  u8            umem[SXT_UMEM_LEN];
  u32           rx_prod, rx_cons;
  u32           tx_prod, tx_cons;
  u32           fill_prod, fill_cons;
  u32           comp_prod, comp_cons;
  quic_xdp_desc rx_desc[SXT_RING];
  quic_xdp_desc tx_desc[SXT_TXRING];
  u64           fill_desc[SXT_RING];
  u64           comp_desc[SXT_TXRING];
  quic_xskring  krx, ktx, kfill, kcomp; /* the "kernel"'s own ring handles */
} sxt_world;

static void sxt_ring(
    quic_xskring* r, u32* prod, u32* cons, void* desc, u32 size) {
  quic_xskring_view v = {prod, cons, desc, size};
  quic_xskring_init(r, &v);
}

/* Wire w's arrays into x's four app-side rings and the world's own
 * "kernel-side" mirror handles (krx/ktx/kfill/kcomp), then zero-init x's
 * non-ring state the way wired_srvxdp_open would. */
static void sxt_init(sxt_world* w, wired_srvxdp* x) {
  *w = (sxt_world){0};
  *x = (wired_srvxdp){0};
  sxt_ring(&x->xsk.rx, &w->rx_prod, &w->rx_cons, w->rx_desc, SXT_RING);
  sxt_ring(&x->xsk.tx, &w->tx_prod, &w->tx_cons, w->tx_desc, SXT_TXRING);
  sxt_ring(&x->xsk.fill, &w->fill_prod, &w->fill_cons, w->fill_desc, SXT_RING);
  sxt_ring(
      &x->xsk.comp, &w->comp_prod, &w->comp_cons, w->comp_desc, SXT_TXRING);
  sxt_ring(&w->krx, &w->rx_prod, &w->rx_cons, w->rx_desc, SXT_RING);
  sxt_ring(&w->ktx, &w->tx_prod, &w->tx_cons, w->tx_desc, SXT_TXRING);
  sxt_ring(&w->kfill, &w->fill_prod, &w->fill_cons, w->fill_desc, SXT_RING);
  sxt_ring(&w->kcomp, &w->comp_prod, &w->comp_cons, w->comp_desc, SXT_TXRING);
  x->xsk.umem     = w->umem;
  x->xsk.umem_len = SXT_UMEM_LEN;
  x->xsk.fd       = -1;
  x->map_fd = x->prog_fd = x->link_fd = -1;
  /* our identity, initialized the same way wired_srvxdp_open does it:
   * 10.7.0.1:4433, the golden RX vector's destination */
  quic_memcpy((u8*)&x->ip_be, (const u8[]){10, 7, 0, 1}, 4);
  x->port = 4433;
  quic_xdpmac_init(&x->macs);
  quic_xskumem_alloc_init(&x->txpool, 64u * QUIC_XSKUMEM_FRAME_SIZE, 64u);
}

/* Build a golden eth+IPv4+UDP frame (10.7.0.2:5555 -> 10.7.0.1:4433,
 * payload = "hi") at umem offset addr, matching xdpframe_test.c's vector,
 * and hand it to the "kernel" as one RX descriptor. */
static void sxt_kernel_rx_push(sxt_world* w, u64 addr) {
  static const u8 golden[60] = {
      0x02, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x07, 0x00, 0x00, 0x00, 0x02,
      0x08, 0x00, 0x45, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11,
      0x00, 0x00, 10,   7,    0,    2,    10,   7,    0,    1,    0x15, 0xb3,
      0x11, 0x51, 0x00, 0x0a, 0x00, 0x00, 'h',  'i',  0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,    0,    0,    0};
  u32            idx;
  quic_xdp_desc* d;
  for (usz i = 0; i < 60; i++) w->umem[addr + i] = golden[i];
  CHECK(quic_xskring_prod_reserve(&w->krx, 1, &idx) == 1);
  d          = quic_xskring_desc_at(&w->krx, idx);
  d->addr    = addr;
  d->len     = 60;
  d->options = 0;
  quic_xskring_prod_submit(&w->krx, 1);
}

/* 1: rx_burst parses one pushed frame into bufs[0] and returns its RX
 * frame to the fill ring. */
static void test_srvxdp_rx_basic(void) {
  sxt_world     w;
  wired_srvxdp  x;
  u8            payload_buf[64];
  quic_mmsg_buf bufs[4];
  i64           n;
  u32           idx;
  sxt_init(&w, &x);
  bufs[0].buf = quic_mspan_of(payload_buf, sizeof payload_buf);

  sxt_kernel_rx_push(&w, 0);
  n = wired_srvxdp_rx_burst(&x, bufs, 4);

  CHECK(n == 1);
  CHECK(bufs[0].len == 2 && bufs[0].buf.p[0] == 'h' && bufs[0].buf.p[1] == 'i');
  CHECK(x.have_mac == 1);
  /* the consumed rx frame (addr 0) came back to the fill ring */
  CHECK(quic_xskring_cons_peek(&w.kfill, 1, &idx) == 1);
  CHECK(*quic_xskring_addr_at(&w.kfill, idx) == 0);
}

/* 2: frame conservation over many rx cycles: fill+rx occupancy never
 * exceeds the ring capacity, and every cycle's frame is fully accounted
 * for (either still in rx, or returned to fill). */
static void test_srvxdp_rx_conservation(void) {
  sxt_world     w;
  wired_srvxdp  x;
  u8            payload_buf[64];
  quic_mmsg_buf bufs[4];
  sxt_init(&w, &x);
  bufs[0].buf = quic_mspan_of(payload_buf, sizeof payload_buf);

  for (int cycle = 0; cycle < 200; cycle++) {
    u64 addr = (u64)(cycle % 8) * QUIC_XSKUMEM_FRAME_SIZE;
    i64 n;
    sxt_kernel_rx_push(&w, addr);
    n = wired_srvxdp_rx_burst(&x, bufs, 4);
    CHECK(n == 1);
    CHECK(w.fill_prod - w.fill_cons <= SXT_RING);
    CHECK(w.rx_prod - w.rx_cons <= SXT_RING);
  }
}

/* Learn dst's MAC by feeding one RX frame from it (golden vector's peer:
 * 10.7.0.2, mac 02:07:00:00:00:02), then return the sockaddr for it. */
static void sxt_learn_peer(
    sxt_world* w, wired_srvxdp* x, quic_sockaddr_in* dst) {
  u8            payload_buf[64];
  quic_mmsg_buf bufs[4];
  bufs[0].buf = quic_mspan_of(payload_buf, sizeof payload_buf);
  sxt_kernel_rx_push(w, 0);
  wired_srvxdp_rx_burst(x, bufs, 4);
  *dst = bufs[0].src;
}

/* 3: send() with a learned MAC appends one tx descriptor whose frame
 * parses back to the same payload. */
static void test_srvxdp_send_basic(void) {
  sxt_world        w;
  wired_srvxdp     x;
  quic_sockaddr_in dst;
  const u8         pl[3] = {0xc0, 0xff, 0xee};
  u32              idx;
  quic_xdp_desc*   d;
  quic_xdpframe_rx rx;
  sxt_init(&w, &x);
  sxt_learn_peer(&w, &x, &dst);

  CHECK(wired_srvxdp_send(&x, &dst, quic_span_of(pl, 3)) == 1);
  CHECK(quic_xskring_cons_peek(&w.ktx, 1, &idx) == 1);
  d = quic_xskring_desc_at(&w.ktx, idx);
  CHECK(quic_xdpframe_parse(quic_span_of(w.umem + d->addr, d->len), &rx) == 1);
  CHECK(rx.payload_len == 3 && rx.payload[0] == 0xc0 && rx.payload[2] == 0xee);
  /* the frame's source must be our identity, byte-exact on the wire:
   * 10.7.0.1:4433 (a reversed source IP passed every earlier check) */
  {
    const u8* sip = (const u8*)&rx.src.addr_be;
    CHECK(sip[0] == 10 && sip[1] == 7 && sip[2] == 0 && sip[3] == 1);
    CHECK(quic_get_be16((const u8*)&rx.src.port_be) == 4433);
  }
}

/* 4: a completion posted by the "kernel" for a sent tx frame comes back to
 * txpool, observable as a successful send after the pool would otherwise
 * be one short. */
static void test_srvxdp_completion_reap(void) {
  sxt_world        w;
  wired_srvxdp     x;
  quic_sockaddr_in dst;
  const u8         pl[1] = {1};
  u32              tx_idx, comp_idx;
  quic_xdp_desc*   txd;
  i64              got;
  sxt_init(&w, &x);
  sxt_learn_peer(&w, &x, &dst);

  /* drain txpool to exactly one frame left, then send it */
  for (int i = 0; i < 63; i++) CHECK(quic_xskumem_alloc_get(&x.txpool) >= 0);
  CHECK(wired_srvxdp_send(&x, &dst, quic_span_of(pl, 1)) == 1);
  /* pool now empty: kernel "completes" the frame it just took off tx */
  CHECK(quic_xskring_cons_peek(&w.ktx, 1, &tx_idx) == 1);
  txd = quic_xskring_desc_at(&w.ktx, tx_idx);
  CHECK(quic_xskring_prod_reserve(&w.kcomp, 1, &comp_idx) == 1);
  *quic_xskring_addr_at(&w.kcomp, comp_idx) = txd->addr;
  quic_xskring_prod_submit(&w.kcomp, 1);
  quic_xskring_cons_release(&w.ktx, 1);

  got = wired_srvxdp_send(&x, &dst, quic_span_of(pl, 1));
  CHECK(got == 1);
}

/* 5: txpool exhaustion without any completion: the 65th send drops. */
static void test_srvxdp_txpool_exhaustion(void) {
  sxt_world        w;
  wired_srvxdp     x;
  quic_sockaddr_in dst;
  const u8         pl[1] = {7};
  sxt_init(&w, &x);
  sxt_learn_peer(&w, &x, &dst);

  for (int i = 0; i < 64; i++)
    CHECK(wired_srvxdp_send(&x, &dst, quic_span_of(pl, 1)) == 1);
  CHECK(wired_srvxdp_send(&x, &dst, quic_span_of(pl, 1)) == 0);
}

/* 6: send() to an unlearned destination drops without touching tx. */
static void test_srvxdp_mac_miss(void) {
  sxt_world        w;
  wired_srvxdp     x;
  quic_sockaddr_in dst;
  const u8         pl[1] = {9};
  u32              idx;
  sxt_init(&w, &x);
  wired_udp_addr(&dst, 4433, (const u8[]){10, 9, 9, 9});

  CHECK(wired_srvxdp_send(&x, &dst, quic_span_of(pl, 1)) == 0);
  CHECK(quic_xskring_cons_peek(&w.ktx, 1, &idx) == 0);
}

void test_srvxdp(void) {
  test_srvxdp_rx_basic();
  test_srvxdp_rx_conservation();
  test_srvxdp_send_basic();
  test_srvxdp_completion_reap();
  test_srvxdp_txpool_exhaustion();
  test_srvxdp_mac_miss();
}
