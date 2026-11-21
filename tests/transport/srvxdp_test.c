#include "ncid_key.h"
#include "test.h"

/* Fake-kernel harness for wired_srvxdp: no mmap, no bpf, no real fd. Every
 * ring is a plain xskring_view over static local arrays (matching
 * xskring_test.c's pattern), and the "kernel" is played by the test code
 * itself calling the very same producer/consumer ops the real kernel would
 * use on its side of each SPSC ring. */

#define SXT_RING 8u
/* tx/comp need to hold every in-flight TX-pool frame at once for the
 * txpool-exhaustion test (SRVXDP_TXPOOL_FRAMES sends with no completion in
 * between), so they are sized to the pool, unlike rx/fill which stay at
 * SXT_RING. xskring_init requires a power-of-two size (its mask = size-1),
 * so round SRVXDP_TXPOOL_FRAMES up to the next one; the real kernel-side
 * TX/comp rings are always a fixed power of two (XSKSETUP_RING_ENTRIES)
 * regardless of the pool's frame count, so this fake harness ring is
 * already bigger than any real one and never limits the test. */
#define SXT_TXRING 1024u
#define SXT_UMEM_FRAMES XSKSETUP_UMEM_FRAMES
#define SXT_UMEM_LEN ((usz)SXT_UMEM_FRAMES * XSKUMEM_FRAME_SIZE)

/* umem is the one multi-megabyte member (SXT_UMEM_LEN bytes): each test
 * function keeps its sxt_world as a `static` local so this lives in BSS,
 * not on the stack. */
typedef struct {
  u8       umem[SXT_UMEM_LEN];
  u32      rx_prod, rx_cons;
  u32      tx_prod, tx_cons;
  u32      fill_prod, fill_cons;
  u32      comp_prod, comp_cons;
  xdp_desc rx_desc[SXT_RING];
  xdp_desc tx_desc[SXT_TXRING];
  u64      fill_desc[SXT_RING];
  u64      comp_desc[SXT_TXRING];
  xskring  krx, ktx, kfill, kcomp; /* the "kernel"'s own ring handles */
} sxt_world;

static void sxt_ring(xskring* r, u32* prod, u32* cons, void* desc, u32 size) {
  xskring_view v = {prod, cons, desc, size};
  xskring_init(r, &v);
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
  x->bpf.map_fd = x->bpf.prog_fd = x->bpf.link_fd = -1;
  /* our port, as wired_srvxdp_open sets it; our address is learned per
   * peer from each received frame's destination */
  x->port = 4433;
  xdpmac_init(&x->macs);
  xskumem_alloc_init(&x->txpool, SRVXDP_TXPOOL_BASE, SRVXDP_TXPOOL_FRAMES);
}

/* Build a golden eth+IPv4+UDP frame (10.7.0.2:5555 -> 10.7.0.1:4433,
 * payload = "hi") at umem offset addr, matching xdpframe_test.c's vector,
 * with byte off XORed by x (x = 0: unchanged), and hand it to the "kernel"
 * as one RX descriptor. */
static void sxt_kernel_rx_push_x(sxt_world* w, u64 addr, usz off, u8 x) {
  static const u8 golden[60] = {
      0x02, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x07, 0x00, 0x00, 0x00, 0x02,
      0x08, 0x00, 0x45, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11,
      0x66, 0xbf, 10,   7,    0,    2,    10,   7,    0,    1,    0x15, 0xb3,
      0x11, 0x51, 0x00, 0x0a, 0x00, 0x00, 'h',  'i',  0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,    0,    0,    0};
  u32       idx;
  xdp_desc* d;
  for (usz i = 0; i < 60; i++) {
    w->umem[addr + i] = golden[i];
  }
  w->umem[addr + off] ^= x;
  CHECK(xskring_prod_reserve(&w->krx, 1, &idx) == 1);
  d          = xskring_desc_at(&w->krx, idx);
  d->addr    = addr;
  d->len     = 60;
  d->options = 0;
  xskring_prod_submit(&w->krx, 1);
}

static void sxt_kernel_rx_push(sxt_world* w, u64 addr) {
  sxt_kernel_rx_push_x(w, addr, 0, 0);
}

/* rx_burst over one pushed frame with byte off XORed by x: the number of
 * datagrams delivered. */
static i64 sxt_rx_mutated(wired_srvxdp* x, sxt_world* w, usz off, u8 v) {
  u8       payload_buf[64];
  mmsg_buf bufs[4];
  bufs[0].buf = wired_mspan_of(payload_buf, sizeof payload_buf);
  sxt_kernel_rx_push_x(w, 0, off, v);
  return wired_srvxdp_rx_burst(x, bufs, 4);
}

/* RFC 791 3.1 / RFC 768 on the shipping receive path: a frame with a bad
 * IP header checksum or a wrong non-zero UDP checksum is dropped; the
 * skip_udp_csum opt-out (veth CHECKSUM_PARTIAL) accepts the UDP case only. */
static void test_srvxdp_rx_drops_bad_headers(void) {
  static sxt_world w;
  wired_srvxdp     x;
  sxt_init(&w, &x);
  CHECK(sxt_rx_mutated(&x, &w, ETH_HDR + 10, 0x01) == 0);
  CHECK(sxt_rx_mutated(&x, &w, 40, 0x12) == 0);
  x.skip_udp_csum = 1;
  CHECK(sxt_rx_mutated(&x, &w, 40, 0x12) == 1);
  CHECK(sxt_rx_mutated(&x, &w, ETH_HDR + 10, 0x01) == 0);
}

/* RFC 791 3.1: TTL 0 with a consistent header checksum (sum 0x9940 - 0x4000
 * = 0x5940, checksum 0xa6bf) is dropped on the shipping receive path. */
static void test_srvxdp_rx_drops_ttl_zero(void) {
  static sxt_world w;
  wired_srvxdp     x;
  u8               payload_buf[64];
  mmsg_buf         bufs[4];
  sxt_init(&w, &x);
  bufs[0].buf = wired_mspan_of(payload_buf, sizeof payload_buf);
  sxt_kernel_rx_push_x(&w, 0, ETH_HDR + 8, 0x40);
  w.umem[ETH_HDR + 10] = 0xa6;
  CHECK(wired_srvxdp_rx_burst(&x, bufs, 4) == 0);
}

/* 1: rx_burst parses one pushed frame into bufs[0] and returns its RX
 * frame to the fill ring. */
static void test_srvxdp_rx_basic(void) {
  static sxt_world w;
  wired_srvxdp     x;
  u8               payload_buf[64];
  mmsg_buf         bufs[4];
  i64              n;
  u32              idx;
  sxt_init(&w, &x);
  bufs[0].buf = wired_mspan_of(payload_buf, sizeof payload_buf);

  sxt_kernel_rx_push(&w, 0);
  n = wired_srvxdp_rx_burst(&x, bufs, 4);

  CHECK(n == 1);
  CHECK(bufs[0].len == 2 && bufs[0].buf.p[0] == 'h' && bufs[0].buf.p[1] == 'i');
  CHECK(x.have_mac == 1);
  /* the consumed rx frame (addr 0) came back to the fill ring */
  CHECK(xskring_cons_peek(&w.kfill, 1, &idx) == 1);
  CHECK(*xskring_addr_at(&w.kfill, idx) == 0);
}

/* 2: frame conservation over many rx cycles: fill+rx occupancy never
 * exceeds the ring capacity, and every cycle's frame is fully accounted
 * for (either still in rx, or returned to fill). */
static void test_srvxdp_rx_conservation(void) {
  static sxt_world w;
  wired_srvxdp     x;
  u8               payload_buf[64];
  mmsg_buf         bufs[4];
  sxt_init(&w, &x);
  bufs[0].buf = wired_mspan_of(payload_buf, sizeof payload_buf);

  for (int cycle = 0; cycle < 200; cycle++) {
    u64 addr = (u64)(cycle % 8) * XSKUMEM_FRAME_SIZE;
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
static void sxt_learn_peer(sxt_world* w, wired_srvxdp* x, sockaddr* dst) {
  u8       payload_buf[64];
  mmsg_buf bufs[4];
  bufs[0].buf = wired_mspan_of(payload_buf, sizeof payload_buf);
  sxt_kernel_rx_push(w, 0);
  wired_srvxdp_rx_burst(x, bufs, 4);
  *dst = bufs[0].src;
}

/* 3: send() with a learned MAC appends one tx descriptor whose frame
 * parses back to the same payload. */
static void test_srvxdp_send_basic(void) {
  static sxt_world w;
  wired_srvxdp     x;
  sockaddr         dst;
  const u8         pl[3] = {0xc0, 0xff, 0xee};
  u32              idx;
  xdp_desc*        d;
  xdpframe_rx      rx;
  sxt_init(&w, &x);
  sxt_learn_peer(&w, &x, &dst);

  CHECK(wired_srvxdp_send(&x, &dst, wired_span_of(pl, 3)) == 1);
  CHECK(xskring_cons_peek(&w.ktx, 1, &idx) == 1);
  d = xskring_desc_at(&w.ktx, idx);
  CHECK(xdpframe_parse(wired_span_of(w.umem + d->addr, d->len), 0, &rx) == 1);
  CHECK(rx.payload_len == 3 && rx.payload[0] == 0xc0 && rx.payload[2] == 0xee);
  /* the frame's source must be our identity, byte-exact on the wire:
   * 10.7.0.1:4433 (a reversed source IP passed every earlier check) */
  {
    const u8* sip = rx.src.addr + 12;
    CHECK(sip[0] == 10 && sip[1] == 7 && sip[2] == 0 && sip[3] == 1);
    CHECK(be_get_be16((const u8*)&rx.src.port_be) == 4433);
  }
}

/* 4: a completion posted by the "kernel" for a sent tx frame comes back to
 * txpool, observable as a successful send after the pool would otherwise
 * be one short. */
static void test_srvxdp_completion_reap(void) {
  static sxt_world w;
  wired_srvxdp     x;
  sockaddr         dst;
  const u8         pl[1] = {1};
  u32              tx_idx, comp_idx;
  xdp_desc*        txd;
  i64              got;
  sxt_init(&w, &x);
  sxt_learn_peer(&w, &x, &dst);

  /* drain txpool to exactly one frame left, then send it */
  for (u32 i = 0; i < SRVXDP_TXPOOL_FRAMES - 1; i++) {
    CHECK(xskumem_alloc_get(&x.txpool) >= 0);
  }
  CHECK(wired_srvxdp_send(&x, &dst, wired_span_of(pl, 1)) == 1);
  /* pool now empty: kernel "completes" the frame it just took off tx */
  CHECK(xskring_cons_peek(&w.ktx, 1, &tx_idx) == 1);
  txd = xskring_desc_at(&w.ktx, tx_idx);
  CHECK(xskring_prod_reserve(&w.kcomp, 1, &comp_idx) == 1);
  *xskring_addr_at(&w.kcomp, comp_idx) = txd->addr;
  xskring_prod_submit(&w.kcomp, 1);
  xskring_cons_release(&w.ktx, 1);

  got = wired_srvxdp_send(&x, &dst, wired_span_of(pl, 1));
  CHECK(got == 1);
}

/* 5: txpool exhaustion without any completion: the (N+1)th send drops,
 * where N = SRVXDP_TXPOOL_FRAMES. */
static void test_srvxdp_txpool_exhaustion(void) {
  static sxt_world w;
  wired_srvxdp     x;
  sockaddr         dst;
  const u8         pl[1] = {7};
  sxt_init(&w, &x);
  sxt_learn_peer(&w, &x, &dst);

  for (u32 i = 0; i < SRVXDP_TXPOOL_FRAMES; i++) {
    CHECK(wired_srvxdp_send(&x, &dst, wired_span_of(pl, 1)) == 1);
  }
  CHECK(wired_srvxdp_send(&x, &dst, wired_span_of(pl, 1)) == 0);
}

/* 6: send() to an unlearned destination drops without touching tx. */
static void test_srvxdp_mac_miss(void) {
  static sxt_world w;
  wired_srvxdp     x;
  sockaddr         dst;
  const u8         pl[1] = {9};
  u32              idx;
  sxt_init(&w, &x);
  wired_udp_addr(&dst, 4433, (const u8[]){10, 9, 9, 9});

  CHECK(wired_srvxdp_send(&x, &dst, wired_span_of(pl, 1)) == 0);
  CHECK(xskring_cons_peek(&w.ktx, 1, &idx) == 0);
}

/* 7: print_stats on a bad fd (no real kernel socket) fails the underlying
 * getsockopt and returns without touching anything -- just proves it does
 * not crash. */
static void test_srvxdp_print_stats_bad_fd(void) {
  wired_srvxdp_print_stats(-1);
}

/* RFC 8200 on the shipping paths: an IPv6 frame ([fd00::2]:5555 ->
 * [fd00::1]:4433, xdpframe_test.c's IPv6 vector) is delivered with its
 * native IPv6 source, and the reply to that peer goes out as IPv6 from the
 * address the peer sent to, with a UDP checksum (RFC 8200 8.1). */
static void test_srvxdp_ipv6_rx_then_send(void) {
  static const u8 g6[64] = {
      0x02, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x07, 0x00, 0x00, 0x00,
      0x02, 0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x11, 0x40,
      0xfd, 0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    2,    0xfd, 0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,    0,    0,    1,    0x15,
      0xb3, 0x11, 0x51, 0x00, 0x0a, 0x76, 0x68, 'h',  'i'};
  static sxt_world w;
  wired_srvxdp     x;
  u8               payload_buf[64];
  mmsg_buf         bufs[4];
  u32              idx;
  xdp_desc*        d;
  xdpframe_rx      rx;
  sxt_init(&w, &x);
  bytes_memcpy(w.umem, g6, 64);
  CHECK(xskring_prod_reserve(&w.krx, 1, &idx) == 1);
  d       = xskring_desc_at(&w.krx, idx);
  d->addr = 0;
  d->len  = 64;
  xskring_prod_submit(&w.krx, 1);
  bufs[0].buf = wired_mspan_of(payload_buf, sizeof payload_buf);
  CHECK(wired_srvxdp_rx_burst(&x, bufs, 4) == 1);
  CHECK(xdpframe_is_v4(bufs[0].src.addr) == 0 && bufs[0].src.addr[15] == 2);
  CHECK(
      wired_srvxdp_send(&x, &bufs[0].src, wired_span_of(payload_buf, 2)) == 1);
  CHECK(xskring_cons_peek(&w.ktx, 1, &idx) == 1);
  d = xskring_desc_at(&w.ktx, idx);
  CHECK(d->len == XDPFRAME_HDRS6 + 2);
  CHECK(xdpframe_parse(wired_span_of(w.umem + d->addr, d->len), 0, &rx) == 1);
  CHECK(rx.src.addr[0] == 0xfd && rx.src.addr[15] == 1);
  CHECK(be_get_be16((const u8*)&rx.src.port_be) == 4433);
  CHECK(rx.our_ip[15] == 2 && rx.dport == 5555);
}

/* RFC 9000 14 / RFC 791 3.2 on the shipping send path: every frame
 * wired_srvxdp_send builds has DF set and a fresh Identification. */
static void test_srvxdp_send_sets_df_unique_id(void) {
  static sxt_world w;
  wired_srvxdp     x;
  sockaddr         dst;
  const u8         pl[1] = {0x40};
  u32              idx;
  const u8*        ip[2];
  sxt_init(&w, &x);
  sxt_learn_peer(&w, &x, &dst);
  CHECK(wired_srvxdp_send(&x, &dst, wired_span_of(pl, 1)) == 1);
  CHECK(wired_srvxdp_send(&x, &dst, wired_span_of(pl, 1)) == 1);
  CHECK(xskring_cons_peek(&w.ktx, 2, &idx) == 2);
  for (u32 i = 0; i < 2; i++) {
    ip[i] = w.umem + xskring_desc_at(&w.ktx, idx + i)->addr + ETH_HDR;
    CHECK(ip[i][6] == 0x40 && ip[i][7] == 0);
  }
  CHECK(be_get_be16(ip[0] + 4) != be_get_be16(ip[1] + 4));
}

/* --- RFC 9000 9: forwarding to the CID's owner ------------------------------
 * Two workers (queue 0 and 1) sharing one 2x2 forwarding mesh and one CID
 * routing key, each over its own fake kernel. */
static void sxt_join_n(wired_srvxdp* x, u32 queue, srvfwd_ring* mesh, u32 n) {
  x->queue_id  = queue;
  x->route_key = test_ncid_key;
  x->fwd       = mesh;
  x->fwd_n     = n;
}

static void sxt_join(wired_srvxdp* x, u32 queue, srvfwd_ring* mesh) {
  sxt_join_n(x, queue, mesh, 2);
}

/* Hand the "kernel" one frame 10.7.0.2:sport -> 10.7.0.1:4433 at umem 0
 * carrying the first qn (<= 20) bytes of a QUIC packet (short or long
 * header) whose DCID routes to core. */
static void sxt_kernel_rx_quic_n(
    sxt_world* w, int is_long, u8 core, u16 sport, usz qn) {
  const xdpframe_tx m = {
      {0x02, 0x07, 0x00, 0x00, 0x00, 0x01},
      {0x02, 0x07, 0x00, 0x00, 0x00, 0x02},
      {sport, 4433},
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 7, 0, 2},
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 7, 0, 1},
      0};
  u8        q[20] = {0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0x77};
  usz       at    = is_long ? 6 : 1;
  u32       idx;
  xdp_desc* d;
  if (is_long) {
    q[0] = 0xc0, q[4] = 1, q[5] = 8;
  }
  q[at + 1] = 0x5a; /* a non-trivial mix input */
  CHECK(ncid_route_encode(q + at, 8, core, &test_ncid_key) == 0);
  CHECK(xskring_prod_reserve(&w->krx, 1, &idx) == 1);
  d       = xskring_desc_at(&w->krx, idx);
  d->addr = 0;
  d->len  = (u32)xdpframe_build(
      wired_mspan_of(w->umem, XSKUMEM_FRAME_SIZE), &m, wired_span_of(q, qn));
  xskring_prod_submit(&w->krx, 1);
}

static void sxt_kernel_rx_quic(sxt_world* w, int is_long, u8 core, u16 sport) {
  sxt_kernel_rx_quic_n(w, is_long, core, sport, 20);
}

/* rx_burst into n (<= 4) slots of one AF_XDP frame each: no payload an
 * XSK frame carries (nor a srvfwd slot) is larger. */
static i64 sxt_burst_n(wired_srvxdp* x, mmsg_buf* b, usz n) {
  static u8 buf[4][XSKSETUP_FRAME_SIZE];
  for (usz i = 0; i < n; i++) {
    b[i].buf = wired_mspan_of(buf[i], sizeof buf[i]);
  }
  return wired_srvxdp_rx_burst(x, b, n);
}

static i64 sxt_burst(wired_srvxdp* x, mmsg_buf* b) {
  return sxt_burst_n(x, b, 1);
}

static u16 sxt_port(const mmsg_buf* b) {
  return be_get_be16((const u8*)&b->src.port_be);
}

/* Queue one forwarded datagram from sport straight into ring r. */
static void sxt_fwd_push(srvfwd_ring* r, u16 sport) {
  static const u8 pl[8] = {0x40, 1, 2, 3, 4, 5, 6, 7};
  xdpframe_rx     rx    = {0};
  wired_udp_addr(&rx.src, sport, (const u8[]){10, 7, 0, 2});
  rx.payload     = pl;
  rx.payload_len = sizeof pl;
  CHECK(srvfwd_push(r, &rx) == 1);
}

/* A short header whose CID names worker 1, arriving on worker 0's queue
 * (a path change moved it, RFC 9000 9), is not served by worker 0: worker
 * 1's next burst returns it with the original source address and payload,
 * so path validation (RFC 9000 8.2, 9.3) sees the new address, and worker 1
 * can answer that address over its own XSK (the peer MAC came along). */
static void test_srvxdp_fwd_to_owner(void) {
  static sxt_world   wa, wb;
  static srvfwd_ring mesh[4];
  wired_srvxdp       a, b;
  mmsg_buf           got;
  sxt_init(&wa, &a);
  sxt_init(&wb, &b);
  sxt_join(&a, 0, mesh);
  sxt_join(&b, 1, mesh);
  sxt_kernel_rx_quic(&wa, 0, 1, 6000);
  CHECK(sxt_burst(&a, &got) == 0);
  CHECK(sxt_burst(&b, &got) == 1);
  CHECK(be_get_be16((const u8*)&got.src.port_be) == 6000);
  CHECK(got.src.addr[12] == 10 && got.src.addr[15] == 2);
  CHECK(got.len == 20 && got.buf.p[0] == 0x40 && got.buf.p[9] == 0x77);
  CHECK(b.have_mac == 1);
  CHECK(wired_srvxdp_send(&b, &got.src, wired_span_of(got.buf.p, 1)) == 1);
  CHECK(sxt_burst(&b, &got) == 0); /* consumed once */
}

/* Served where it arrived: a CID naming this worker, a long header (the
 * handshake stays on the queue its 4-tuple hashes to; a client's first
 * Initial DCID is random, RFC 9000 7.2), a CID naming a worker that does
 * not exist (core 5 of 2), and any CID when forwarding is off. */
static void test_srvxdp_fwd_keeps_local(void) {
  static sxt_world   w;
  static srvfwd_ring mesh[4];
  wired_srvxdp       a;
  mmsg_buf           got;
  sxt_init(&w, &a);
  sxt_join(&a, 0, mesh);
  sxt_kernel_rx_quic(&w, 0, 0, 6000);
  CHECK(sxt_burst(&a, &got) == 1);
  sxt_kernel_rx_quic(&w, 1, 1, 6000);
  CHECK(sxt_burst(&a, &got) == 1);
  sxt_kernel_rx_quic(&w, 0, 5, 6000);
  CHECK(sxt_burst(&a, &got) == 1);
  a.fwd = 0;
  sxt_kernel_rx_quic(&w, 0, 1, 6000);
  CHECK(sxt_burst(&a, &got) == 1);
  CHECK(mesh[2].prod == 0);
}

/* RFC 9000 9 under load: when the owner's ring from this queue is full the
 * datagram is dropped and counted, never served by the worker it landed on
 * (that worker has no connection for it; QUIC loss recovery resends). */
static void test_srvxdp_fwd_full_ring_drops(void) {
  static sxt_world   w;
  static srvfwd_ring mesh[4];
  wired_srvxdp       a;
  mmsg_buf           got;
  sxt_init(&w, &a);
  sxt_join(&a, 0, mesh);
  for (u32 i = 0; i < SRVFWD_DEPTH; i++) {
    sxt_fwd_push(&mesh[2], 7000);
  }
  sxt_kernel_rx_quic(&w, 0, 1, 6000);
  CHECK(sxt_burst(&a, &got) == 0);
  CHECK(mesh[2].drops == 1);
}

/* One burst carries forwarded datagrams first, then the queue's own. */
static void test_srvxdp_fwd_mixes_with_local(void) {
  static sxt_world   w;
  static srvfwd_ring mesh[4];
  wired_srvxdp       b;
  mmsg_buf           got[4];
  sxt_init(&w, &b);
  sxt_join(&b, 1, mesh);
  sxt_fwd_push(&mesh[2], 7000);
  sxt_kernel_rx_quic(&w, 0, 1, 6000);
  CHECK(sxt_burst_n(&b, got, 4) == 2);
  CHECK(sxt_port(&got[0]) == 7000 && sxt_port(&got[1]) == 6000);
}

/* Workers 0 and 2 of three queue for worker 1 (rings [1*3+0] and [1*3+2];
 * its own ring [1*3+1] stays empty, as in production). The owner takes one
 * forwarded datagram per burst (half of 2 slots) and must not keep reading
 * the same ring while the other waits. */
static void test_srvxdp_fwd_rotates_rings(void) {
  static sxt_world   w;
  static srvfwd_ring mesh[9];
  wired_srvxdp       b;
  mmsg_buf           got[2];
  sxt_init(&w, &b);
  sxt_join_n(&b, 1, mesh, 3);
  sxt_fwd_push(&mesh[3], 7000);
  sxt_fwd_push(&mesh[3], 7001);
  sxt_fwd_push(&mesh[5], 8000);
  CHECK(sxt_burst_n(&b, got, 2) == 1);
  CHECK(sxt_port(&got[0]) == 7000);
  CHECK(sxt_burst_n(&b, got, 2) == 1);
  CHECK(sxt_port(&got[0]) == 8000);
  CHECK(sxt_burst_n(&b, got, 2) == 1);
  CHECK(sxt_port(&got[0]) == 7001);
}

/* The DCID's routing bytes need 1 + NCID_ROUTE_MIN_LEN payload bytes: one
 * fewer is served where it landed, exactly that many is forwarded. */
static void test_srvxdp_fwd_min_len_boundary(void) {
  static sxt_world   w;
  static srvfwd_ring mesh[4];
  wired_srvxdp       a;
  mmsg_buf           got;
  sxt_init(&w, &a);
  sxt_join(&a, 0, mesh);
  sxt_kernel_rx_quic_n(&w, 0, 1, 6000, NCID_ROUTE_MIN_LEN);
  CHECK(sxt_burst(&a, &got) == 1);
  sxt_kernel_rx_quic_n(&w, 0, 1, 6000, NCID_ROUTE_MIN_LEN + 1);
  CHECK(sxt_burst(&a, &got) == 0);
  CHECK(mesh[2].prod == 1);
}

void test_srvxdp(void) {
  test_srvxdp_ipv6_rx_then_send();
  test_srvxdp_rx_basic();
  test_srvxdp_rx_conservation();
  test_srvxdp_rx_drops_bad_headers();
  test_srvxdp_rx_drops_ttl_zero();
  test_srvxdp_send_basic();
  test_srvxdp_send_sets_df_unique_id();
  test_srvxdp_completion_reap();
  test_srvxdp_txpool_exhaustion();
  test_srvxdp_mac_miss();
  test_srvxdp_print_stats_bad_fd();
  test_srvxdp_fwd_to_owner();
  test_srvxdp_fwd_keeps_local();
  test_srvxdp_fwd_full_ring_drops();
  test_srvxdp_fwd_mixes_with_local();
  test_srvxdp_fwd_rotates_rings();
  test_srvxdp_fwd_min_len_boundary();
}
