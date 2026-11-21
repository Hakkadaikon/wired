#include "app/http3/server/srvfwd/srvfwd.h"

#include "common/platform/thread/thread.h"
#include "test.h"

/* @file
 * The forwarding ring alone: empty, ordering, full (drop + counter), and
 * wrap of both the slot index and the u32 counters. */

/* A datagram whose single payload byte is tag, from port tag. */
static xdpframe_rx sfw_rx(u8* byte, u8 tag) {
  xdpframe_rx rx = {0};
  *byte          = tag;
  rx.src.port_be = tag;
  rx.payload     = byte;
  rx.payload_len = 1;
  return rx;
}

static int sfw_push(srvfwd_ring* r, u8 tag) {
  u8          b;
  xdpframe_rx rx = sfw_rx(&b, tag);
  return srvfwd_push(r, &rx);
}

/* Peek one, check it carries tag (payload and source), release it. */
static void sfw_expect(srvfwd_ring* r, u8 tag) {
  const xdpframe_rx* rx = srvfwd_peek(r);
  CHECK(rx != 0);
  if (!rx) {
    return;
  }
  CHECK(rx->payload_len == 1 && rx->payload[0] == tag);
  CHECK(rx->src.port_be == tag);
  srvfwd_pop(r);
}

static void test_srvfwd_empty(void) {
  static srvfwd_ring r;
  r = (srvfwd_ring){0};
  CHECK(srvfwd_peek(&r) == 0);
}

/* FIFO: pushed 1..5, popped 1..5, then empty again. */
static void test_srvfwd_order(void) {
  static srvfwd_ring r;
  r = (srvfwd_ring){0};
  for (u8 i = 1; i <= 5; i++) {
    CHECK(sfw_push(&r, i) == 1);
  }
  for (u8 i = 1; i <= 5; i++) {
    sfw_expect(&r, i);
  }
  CHECK(srvfwd_peek(&r) == 0);
}

/* DEPTH pushes fit, the next is dropped and counted, the queued ones are
 * untouched, and one pop makes room again. */
static void test_srvfwd_full_drops(void) {
  static srvfwd_ring r;
  r = (srvfwd_ring){0};
  for (u32 i = 0; i < SRVFWD_DEPTH; i++) {
    CHECK(sfw_push(&r, (u8)i) == 1);
  }
  CHECK(sfw_push(&r, 0xee) == 0);
  CHECK(r.drops == 1);
  sfw_expect(&r, 0);
  CHECK(sfw_push(&r, 0xee) == 1);
  for (u32 i = 1; i < SRVFWD_DEPTH; i++) {
    sfw_expect(&r, (u8)i);
  }
  sfw_expect(&r, 0xee);
  CHECK(r.drops == 1);
}

/* A payload longer than a slot is dropped and counted. */
static void test_srvfwd_oversize_drops(void) {
  static srvfwd_ring r;
  u8                 b;
  xdpframe_rx        rx = sfw_rx(&b, 1);
  r                     = (srvfwd_ring){0};
  rx.payload_len        = XSKSETUP_FRAME_SIZE + 1;
  CHECK(srvfwd_push(&r, &rx) == 0);
  CHECK(r.drops == 1 && srvfwd_peek(&r) == 0);
}

/* Counters starting just below 2^32 wrap through zero while the slot index
 * cycles the ring several times; order holds throughout. */
static void test_srvfwd_wrap(void) {
  static srvfwd_ring r;
  r      = (srvfwd_ring){0};
  r.prod = r.cons = 0xfffffffdu;
  for (u32 i = 0; i < 3 * SRVFWD_DEPTH; i++) {
    CHECK(sfw_push(&r, (u8)i) == 1);
    CHECK(sfw_push(&r, (u8)(i + 100)) == 1);
    sfw_expect(&r, (u8)i);
    sfw_expect(&r, (u8)(i + 100));
  }
  CHECK(srvfwd_peek(&r) == 0 && r.drops == 0);
}

/* Real producer and consumer threads: every datagram that was not dropped
 * arrives once, whole (payload and source agree), and in push order. */
#define SFW_STRESS_N 20000u

typedef struct {
  srvfwd_ring*  r;
  volatile u32* stop;
  u32           received;
  u32           bad; /* out of order or torn */
} sfw_consumer;

static void sfw_producer_fn(void* argp) {
  srvfwd_ring* r = (srvfwd_ring*)argp;
  for (u32 i = 1; i <= SFW_STRESS_N; i++) {
    u8          b[4];
    xdpframe_rx rx = {0};
    be_put_be32(b, i);
    rx.src.flowinfo = i;
    rx.payload      = b;
    rx.payload_len  = 4;
    srvfwd_push(r, &rx);
  }
}

/* Pop everything queued now; 0 when the ring was empty. */
static u32 sfw_consume(sfw_consumer* c, u32* last) {
  u32 got = 0;
  for (const xdpframe_rx* rx = srvfwd_peek(c->r); rx; rx = srvfwd_peek(c->r)) {
    u32 v = be_get_be32(rx->payload);
    c->bad += v <= *last || v != rx->src.flowinfo;
    *last = v;
    srvfwd_pop(c->r);
    got++;
  }
  c->received += got;
  return got;
}

static void sfw_consumer_fn(void* argp) {
  sfw_consumer* c    = (sfw_consumer*)argp;
  u32           last = 0;
  while (!__atomic_load_n(c->stop, __ATOMIC_ACQUIRE)) {
    sfw_consume(c, &last);
  }
  sfw_consume(c, &last); /* what was published just before the stop */
}

static void test_srvfwd_thread_stress(void) {
  static srvfwd_ring r;
  volatile u32       stop = 0;
  sfw_consumer       c    = {&r, &stop, 0, 0};
  wired_thread       pt = {0}, ct = {0};
  r = (srvfwd_ring){0};
  CHECK(wired_thread_start(&ct, sfw_consumer_fn, &c) == 0);
  CHECK(wired_thread_start(&pt, sfw_producer_fn, &r) == 0);
  CHECK(wired_thread_join(&pt) == 0);
  __atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
  CHECK(wired_thread_join(&ct) == 0);
  CHECK(c.received + r.drops == SFW_STRESS_N);
  CHECK(c.bad == 0 && c.received > 0);
}

void test_srvfwd(void) {
  test_srvfwd_empty();
  test_srvfwd_order();
  test_srvfwd_full_drops();
  test_srvfwd_oversize_drops();
  test_srvfwd_wrap();
  test_srvfwd_thread_stress();
}
