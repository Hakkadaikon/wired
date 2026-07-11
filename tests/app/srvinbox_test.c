#include "app/http3/server/srvinbox/srvinbox.h"

#include "app/http3/server/srvrun/srvrun.h"
#include "common/platform/thread/thread.h"
#include "test.h"

/* @file
 * Phase E (tasks/loopeng/srvinbox-mesh): the SPSC inbox ring itself
 * (push/pop round-trip, drop-on-full, wrap-around, a real 1P1C thread
 * stress) and srvrun.c's broadcast registry wiring (single-worker fallback
 * untouched, a real 2-worker mesh delivering across threads). */

static const u8 sib_msg_a[] = {1, 2, 3};
static const u8 sib_msg_b[] = {4, 5, 6, 7};

/* Basic push/pop round-trip: one message in, the same bytes out. */
static void test_srvinbox_push_pop_roundtrip(void) {
  wired_srvinbox_ring r;
  u8                  out[WIRED_SRVINBOX_SLOT_MAX];
  usz                 n;
  wired_srvinbox_ring_init(&r);
  CHECK(wired_srvinbox_push(&r, sib_msg_a, sizeof sib_msg_a) == 1);
  n = wired_srvinbox_pop(&r, out, sizeof out);
  CHECK(n == sizeof sib_msg_a);
  for (usz i = 0; i < sizeof sib_msg_a; i++) CHECK(out[i] == sib_msg_a[i]);
}

/* Popping an empty ring returns 0 and leaves nothing behind. */
static void test_srvinbox_pop_empty(void) {
  wired_srvinbox_ring r;
  u8                  out[WIRED_SRVINBOX_SLOT_MAX];
  wired_srvinbox_ring_init(&r);
  CHECK(wired_srvinbox_pop(&r, out, sizeof out) == 0);
}

/* Pushing past depth drops (0 returned) without disturbing what is already
 * queued; draining then still yields the first DEPTH messages in order. */
static void test_srvinbox_drop_when_full(void) {
  wired_srvinbox_ring r;
  u8                  out[WIRED_SRVINBOX_SLOT_MAX];
  wired_srvinbox_ring_init(&r);
  for (u32 i = 0; i < WIRED_SRVINBOX_DEPTH; i++) {
    u8 b = (u8)(i + 1);
    CHECK(wired_srvinbox_push(&r, &b, 1) == 1);
  }
  CHECK(wired_srvinbox_push(&r, sib_msg_a, 1) == 0); /* ring full: dropped */
  for (u32 i = 0; i < WIRED_SRVINBOX_DEPTH; i++) {
    CHECK(wired_srvinbox_pop(&r, out, sizeof out) == 1);
    CHECK(out[0] == (u8)(i + 1));
  }
  CHECK(wired_srvinbox_pop(&r, out, sizeof out) == 0); /* drained */
}

/* A payload longer than WIRED_SRVINBOX_SLOT_MAX is rejected outright. */
static void test_srvinbox_push_oversize_rejected(void) {
  wired_srvinbox_ring r;
  u8                  big[WIRED_SRVINBOX_SLOT_MAX + 1] = {0};
  wired_srvinbox_ring_init(&r);
  CHECK(wired_srvinbox_push(&r, big, sizeof big) == 0);
}

/* Wrap-around across many more pushes than DEPTH: each push/pop pair keeps
 * the ring at depth 1, so nothing is ever dropped and every value survives
 * the round trip, exercising the slot-index wraparound many times over. */
static void test_srvinbox_wrap_around(void) {
  wired_srvinbox_ring r;
  u8                  out[WIRED_SRVINBOX_SLOT_MAX];
  wired_srvinbox_ring_init(&r);
  for (u32 i = 0; i < WIRED_SRVINBOX_DEPTH * 10; i++) {
    u8 b = (u8)(i & 0xff);
    CHECK(wired_srvinbox_push(&r, &b, 1) == 1);
    CHECK(wired_srvinbox_pop(&r, out, sizeof out) == 1);
    CHECK(out[0] == b);
  }
}

/* An undersized destination buffer does not consume the queued message --
 * it stays available for a later pop with enough room. */
static void test_srvinbox_pop_undersized_dst_leaves_slot(void) {
  wired_srvinbox_ring r;
  u8                  small[2];
  u8                  big[WIRED_SRVINBOX_SLOT_MAX];
  wired_srvinbox_ring_init(&r);
  CHECK(wired_srvinbox_push(&r, sib_msg_b, sizeof sib_msg_b) == 1);
  CHECK(wired_srvinbox_pop(&r, small, sizeof small) == 0);
  CHECK(wired_srvinbox_pop(&r, big, sizeof big) == sizeof sib_msg_b);
}

/* Real 1P1C thread stress: a producer thread pushes as fast as it can, a
 * consumer thread pops as fast as it can; after both join, sent - dropped
 * must equal received (tasks/loopeng/srvinbox-mesh S-011 PrefixDelivery, no
 * loss except drop, no duplication). */
#define SIB_STRESS_N 20000

typedef struct {
  wired_srvinbox_ring* r;
  u32                  sent;
  u32                  dropped;
} sib_stress_producer_arg;

typedef struct {
  wired_srvinbox_ring* r;
  volatile u32*        stop;
  u32                  received;
} sib_stress_consumer_arg;

static void sib_stress_producer_fn(void* argp) {
  sib_stress_producer_arg* a = (sib_stress_producer_arg*)argp;
  u8                        b = 0;
  for (u32 i = 0; i < SIB_STRESS_N; i++) {
    if (wired_srvinbox_push(a->r, &b, 1))
      a->sent++;
    else
      a->dropped++;
  }
}

static void sib_stress_consumer_fn(void* argp) {
  sib_stress_consumer_arg* a = (sib_stress_consumer_arg*)argp;
  u8                        out[WIRED_SRVINBOX_SLOT_MAX];
  for (;;) {
    usz n = wired_srvinbox_pop(a->r, out, sizeof out);
    if (n) {
      a->received++;
      continue;
    }
    if (__atomic_load_n(a->stop, __ATOMIC_ACQUIRE)) {
      /* Drain whatever the producer published just before it finished. */
      while (wired_srvinbox_pop(a->r, out, sizeof out)) a->received++;
      return;
    }
  }
}

static void test_srvinbox_thread_stress(void) {
  wired_srvinbox_ring     r;
  volatile u32            stop = 0;
  sib_stress_producer_arg pa   = {&r, 0, 0};
  sib_stress_consumer_arg ca   = {&r, &stop, 0};
  wired_thread             pt = {0, 0, 0};
  wired_thread             ct = {0, 0, 0};
  wired_srvinbox_ring_init(&r);
  CHECK(wired_thread_start(&ct, sib_stress_consumer_fn, &ca) == 0);
  CHECK(wired_thread_start(&pt, sib_stress_producer_fn, &pa) == 0);
  CHECK(wired_thread_join(&pt) == 0);
  __atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
  CHECK(wired_thread_join(&ct) == 0);
  CHECK(pa.sent + pa.dropped == SIB_STRESS_N);
  CHECK(pa.sent == ca.received);
}

/* Broadcast registry, single-worker (n_total<=1): wired_server_broadcast_
 * datagram must keep using the pre-Phase-E direct fan-out untouched --
 * exercised in full by srvrun_test.c's existing broadcast tests (unchanged
 * by this task); here just confirm register/unregister with n_total=1 is a
 * harmless no-op around that path (no crash, still returns 1). */
static void test_srvinbox_registry_single_worker_noop(void) {
  wired_srvinbox_ring row[1];
  wired_srvinbox_ring_init(&row[0]);
  wired_srvrun_broadcast_register(0, 1, row);
  CHECK(
      wired_server_broadcast_datagram(
          quic_span_of(sib_msg_a, sizeof sib_msg_a)) == 1);
  wired_srvrun_broadcast_unregister();
}

/* Real 2-worker mesh: two threads each register their own inbox row (a 2x2
 * mesh, srvrun.c owns the N*N wiring internally -- this test only supplies
 * each worker's own row and calls the public API), worker A broadcasts, and
 * worker B's own row[A] receives it -- proven by popping row[A] directly
 * (the delivery contract), not by reaching into worker A's internals. tid-
 * keyed registration (wired_thread_tid()) means this needs two real threads:
 * the same thread cannot hold two mesh slots at once. */
typedef struct {
  wired_srvinbox_ring* row;   /**< this worker's own N-ring row */
  int                  index; /**< this worker's mesh index */
} sib_mesh_worker_arg;

static volatile u32 sib_mesh_a_registered;
static volatile u32 sib_mesh_b_registered;
static volatile u32 sib_mesh_b_may_check;

static void sib_mesh_worker_a_fn(void* argp) {
  sib_mesh_worker_arg* a = (sib_mesh_worker_arg*)argp;
  wired_srvrun_broadcast_register(a->index, 2, a->row);
  __atomic_store_n(&sib_mesh_a_registered, 1, __ATOMIC_RELEASE);
  while (!__atomic_load_n(&sib_mesh_b_registered, __ATOMIC_ACQUIRE))
    ;
  wired_server_broadcast_datagram(quic_span_of(sib_msg_b, sizeof sib_msg_b));
  __atomic_store_n(&sib_mesh_b_may_check, 1, __ATOMIC_RELEASE);
  wired_srvrun_broadcast_unregister();
}

static void sib_mesh_worker_b_fn(void* argp) {
  sib_mesh_worker_arg* a = (sib_mesh_worker_arg*)argp;
  wired_srvrun_broadcast_register(a->index, 2, a->row);
  __atomic_store_n(&sib_mesh_b_registered, 1, __ATOMIC_RELEASE);
  while (!__atomic_load_n(&sib_mesh_b_may_check, __ATOMIC_ACQUIRE))
    ;
  wired_srvrun_broadcast_unregister();
}

static void test_srvinbox_registry_two_worker_mesh_delivers(void) {
  wired_srvinbox_ring row_a[2]; /* worker A's own row: row_a[j] fed by j */
  wired_srvinbox_ring row_b[2]; /* worker B's own row: row_b[j] fed by j */
  sib_mesh_worker_arg aarg = {row_a, 0};
  sib_mesh_worker_arg barg = {row_b, 1};
  wired_thread          ta = {0, 0, 0};
  wired_thread          tb = {0, 0, 0};
  u8                    out[WIRED_SRVINBOX_SLOT_MAX];
  for (int i = 0; i < 2; i++) {
    wired_srvinbox_ring_init(&row_a[i]);
    wired_srvinbox_ring_init(&row_b[i]);
  }
  sib_mesh_a_registered = 0;
  sib_mesh_b_registered = 0;
  sib_mesh_b_may_check  = 0;
  CHECK(wired_thread_start(&ta, sib_mesh_worker_a_fn, &aarg) == 0);
  CHECK(wired_thread_start(&tb, sib_mesh_worker_b_fn, &barg) == 0);
  CHECK(wired_thread_join(&ta) == 0);
  CHECK(wired_thread_join(&tb) == 0);
  /* Worker B's own row, column 0 (worker A's source column), holds A's
   * broadcast -- delivered through wired_server_broadcast_datagram alone,
   * never by writing worker B's ring directly. */
  CHECK(wired_srvinbox_pop(&row_b[0], out, sizeof out) == sizeof sib_msg_b);
  for (usz i = 0; i < sizeof sib_msg_b; i++) CHECK(out[i] == sib_msg_b[i]);
  /* Worker A's own row also received its own broadcast (source == target
   * included, tasks/loopeng/srvinbox-mesh S-014's own-row inclusion). */
  CHECK(wired_srvinbox_pop(&row_a[0], out, sizeof out) == sizeof sib_msg_b);
}

void test_srvinbox(void) {
  test_srvinbox_push_pop_roundtrip();
  test_srvinbox_pop_empty();
  test_srvinbox_drop_when_full();
  test_srvinbox_push_oversize_rejected();
  test_srvinbox_wrap_around();
  test_srvinbox_pop_undersized_dst_leaves_slot();
  test_srvinbox_thread_stress();
  test_srvinbox_registry_single_worker_noop();
  test_srvinbox_registry_two_worker_mesh_delivers();
}
