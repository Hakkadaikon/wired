#include "app/moqt/run/moqtrel.h"

#include "app/moqt/run/moqtrun.h"
#include "test.h"

/* Reliable-relay ring: append/cursor/reclaim arithmetic and the hold,
 * release and stall decisions, driven directly (no io, no hub). */

_Static_assert(
    WIRED_MOQTREL_MAX_SUBS == WIRED_MOQTRUN_MAX_SUBS,
    "moqtrel mirrors the hub's sub table size");

#define MOQTREL_TEST_BUF WIRED_SRVLOOP_WT_BUF_CAP

static moqtrel_buf g_moqtrel_rb;
static u8          g_moqtrel_src[WIRED_MOQTREL_CAP];

/* Append n pattern bytes (the byte at absolute offset o is o & 0xff)
 * at the ring's current tail; returns moqtrel_append's result. */
static int moqtrel_test_fill(usz n) {
  u64 base = g_moqtrel_rb.tail;
  for (usz i = 0; i < n; i++) g_moqtrel_src[i] = (u8)((base + i) & 0xff);
  return moqtrel_append(&g_moqtrel_rb, wired_span_of(g_moqtrel_src, n));
}

static void test_moqtrel_append_hold_at_watermark(void) {
  moqtrel_reset(&g_moqtrel_rb);
  CHECK(moqtrel_test_fill(MOQTREL_TEST_BUF) == 1);
  CHECK(moqtrel_should_hold(&g_moqtrel_rb) == 0);
  CHECK(moqtrel_test_fill(1) == 1);
  CHECK(moqtrel_should_hold(&g_moqtrel_rb) == 1);
  g_moqtrel_rb.held = 1; /* hub applied the hold */
  CHECK(moqtrel_should_hold(&g_moqtrel_rb) == 0);
}

static void test_moqtrel_hold_leaves_room_for_window(void) {
  moqtrel_reset(&g_moqtrel_rb);
  CHECK(moqtrel_test_fill(MOQTREL_TEST_BUF + 1) == 1);
  CHECK(moqtrel_should_hold(&g_moqtrel_rb) == 1);
  /* a full already-advertised window still fits after the hold lands */
  CHECK(moqtrel_test_fill(MOQTREL_TEST_BUF) == 1);
  CHECK(g_moqtrel_rb.tail - g_moqtrel_rb.head <= WIRED_MOQTREL_CAP);
}

static void test_moqtrel_append_full_reports_overflow(void) {
  moqtrel_reset(&g_moqtrel_rb);
  CHECK(moqtrel_test_fill(WIRED_MOQTREL_CAP) == 1);
  CHECK(moqtrel_test_fill(1) == 0);
  CHECK(g_moqtrel_rb.tail == WIRED_MOQTREL_CAP); /* nothing written */
}

static void test_moqtrel_next_round_span_starts_at_cursor(void) {
  static const u8 five[5] = {1, 2, 3, 4, 5};
  moqtrel_reset(&g_moqtrel_rb);
  g_moqtrel_rb.subs[0].active = 1;
  CHECK(moqtrel_append(&g_moqtrel_rb, wired_span_of(five, 5)) == 1);
  wired_span r = moqtrel_next_round(&g_moqtrel_rb, 0);
  CHECK(r.n == 5);
  CHECK(r.p == g_moqtrel_rb.buf);
  CHECK(r.p[0] == 1 && r.p[4] == 5);
  moqtrel_note_sent(&g_moqtrel_rb, 0, 2, 0);
  r = moqtrel_next_round(&g_moqtrel_rb, 0);
  CHECK(r.n == 3);
  CHECK(r.p == g_moqtrel_rb.buf + 2);
  CHECK(r.p[0] == 3);
}

static void test_moqtrel_next_round_capped_by_round_max(void) {
  moqtrel_reset(&g_moqtrel_rb);
  g_moqtrel_rb.subs[0].active = 1;
  CHECK(moqtrel_test_fill(WIRED_MOQTREL_ROUND_MAX + 1) == 1);
  CHECK(moqtrel_next_round(&g_moqtrel_rb, 0).n == WIRED_MOQTREL_ROUND_MAX);
}

static void test_moqtrel_next_round_stops_at_ring_end(void) {
  moqtrel_reset(&g_moqtrel_rb);
  g_moqtrel_rb.subs[0].active = 1;
  CHECK(moqtrel_test_fill(WIRED_MOQTREL_CAP - 1) == 1);
  moqtrel_note_sent(&g_moqtrel_rb, 0, WIRED_MOQTREL_CAP - 1, 0);
  moqtrel_reclaim(&g_moqtrel_rb);
  CHECK(g_moqtrel_rb.head == WIRED_MOQTREL_CAP - 1);
  CHECK(moqtrel_test_fill(2) == 1); /* crosses the physical ring end */
  wired_span r = moqtrel_next_round(&g_moqtrel_rb, 0);
  CHECK(r.n == 1); /* cut at the ring end */
  CHECK(r.p == g_moqtrel_rb.buf + WIRED_MOQTREL_CAP - 1);
  CHECK(r.p[0] == (u8)((WIRED_MOQTREL_CAP - 1) & 0xff));
  moqtrel_note_sent(&g_moqtrel_rb, 0, 1, 0);
  r = moqtrel_next_round(&g_moqtrel_rb, 0);
  CHECK(r.n == 1); /* continues from physical offset 0 */
  CHECK(r.p == g_moqtrel_rb.buf);
  CHECK(r.p[0] == (u8)(WIRED_MOQTREL_CAP & 0xff));
}

static void test_moqtrel_note_sent_advances_cursor(void) {
  moqtrel_reset(&g_moqtrel_rb);
  g_moqtrel_rb.subs[0].active = 1;
  CHECK(moqtrel_test_fill(10) == 1);
  moqtrel_note_sent(&g_moqtrel_rb, 0, 4, 777);
  CHECK(g_moqtrel_rb.subs[0].sent == 4);
  CHECK(g_moqtrel_rb.subs[0].last_ok_ms == 777);
  moqtrel_note_sent(&g_moqtrel_rb, 0, 6, 900);
  CHECK(g_moqtrel_rb.subs[0].sent == 10);
  CHECK(moqtrel_next_round(&g_moqtrel_rb, 0).n == 0); /* caught up */
}

static void test_moqtrel_reclaim_follows_slowest(void) {
  moqtrel_reset(&g_moqtrel_rb);
  g_moqtrel_rb.subs[0].active = 1;
  g_moqtrel_rb.subs[1].active = 1;
  CHECK(moqtrel_test_fill(100) == 1);
  moqtrel_note_sent(&g_moqtrel_rb, 0, 100, 0);
  moqtrel_note_sent(&g_moqtrel_rb, 1, 40, 0);
  moqtrel_reclaim(&g_moqtrel_rb);
  CHECK(g_moqtrel_rb.head == 40); /* the slowest cursor, not the fastest */
}

static void test_moqtrel_reclaim_skips_abandoned_sub(void) {
  moqtrel_reset(&g_moqtrel_rb);
  g_moqtrel_rb.subs[0].active = 1;
  g_moqtrel_rb.subs[1].active = 1;
  CHECK(moqtrel_test_fill(100) == 1);
  moqtrel_note_sent(&g_moqtrel_rb, 0, 100, 0);
  moqtrel_note_sent(&g_moqtrel_rb, 1, 40, 0);
  g_moqtrel_rb.subs[1].shed = 1; /* given up: must not pin head */
  moqtrel_reclaim(&g_moqtrel_rb);
  CHECK(g_moqtrel_rb.head == 100);
}

static void test_moqtrel_reclaim_skips_detached_sub(void) {
  moqtrel_reset(&g_moqtrel_rb);
  g_moqtrel_rb.subs[0].active = 1;
  g_moqtrel_rb.subs[1].active = 1;
  CHECK(moqtrel_test_fill(100) == 1);
  moqtrel_note_sent(&g_moqtrel_rb, 0, 70, 0);
  moqtrel_note_sent(&g_moqtrel_rb, 1, 10, 0);
  g_moqtrel_rb.subs[1].active = 0; /* session closed */
  moqtrel_reclaim(&g_moqtrel_rb);
  CHECK(g_moqtrel_rb.head == 70);
  g_moqtrel_rb.subs[0].active = 0; /* no pinning sub left */
  moqtrel_reclaim(&g_moqtrel_rb);
  CHECK(g_moqtrel_rb.head == g_moqtrel_rb.tail);
}

static void test_moqtrel_release_at_low_watermark(void) {
  moqtrel_reset(&g_moqtrel_rb);
  g_moqtrel_rb.subs[0].active = 1;
  CHECK(moqtrel_test_fill(MOQTREL_TEST_BUF / 2 + 1) == 1);
  g_moqtrel_rb.held = 1;
  CHECK(moqtrel_should_release(&g_moqtrel_rb) == 0); /* one byte above */
  moqtrel_note_sent(&g_moqtrel_rb, 0, 1, 0);
  moqtrel_reclaim(&g_moqtrel_rb);
  CHECK(moqtrel_should_release(&g_moqtrel_rb) == 1); /* used == BUF/2 */
  g_moqtrel_rb.held = 0;
  CHECK(moqtrel_should_release(&g_moqtrel_rb) == 0); /* nothing to release */
}

static void test_moqtrel_stalled_after_timeout(void) {
  moqtrel_reset(&g_moqtrel_rb);
  g_moqtrel_rb.subs[0].active = 1;
  CHECK(moqtrel_test_fill(10) == 1);
  moqtrel_note_sent(&g_moqtrel_rb, 0, 0, 1000); /* clock anchor */
  CHECK(moqtrel_stalled(&g_moqtrel_rb, 0, 1000 + WIRED_MOQTREL_STALL_MS) == 0);
  CHECK(moqtrel_stalled(&g_moqtrel_rb, 0, 1001 + WIRED_MOQTREL_STALL_MS) == 1);
  g_moqtrel_rb.subs[0].shed = 1; /* already shed: never stalls again */
  CHECK(moqtrel_stalled(&g_moqtrel_rb, 0, 1001 + WIRED_MOQTREL_STALL_MS) == 0);
  g_moqtrel_rb.subs[0].shed = 0;
  moqtrel_note_sent(&g_moqtrel_rb, 0, 10, 1000); /* caught up: no stall */
  CHECK(moqtrel_stalled(&g_moqtrel_rb, 0, 1001 + WIRED_MOQTREL_STALL_MS) == 0);
  CHECK(moqtrel_stalled(&g_moqtrel_rb, 1, 99999999) == 0); /* inactive */
}

static void test_moqtrel_all_done_when_subs_finish(void) {
  moqtrel_reset(&g_moqtrel_rb);
  CHECK(moqtrel_all_done(&g_moqtrel_rb) == 1); /* vacuously done */
  g_moqtrel_rb.subs[0].active = 1;
  CHECK(moqtrel_all_done(&g_moqtrel_rb) == 0);
  g_moqtrel_rb.subs[0].fin_done = 1;
  CHECK(moqtrel_all_done(&g_moqtrel_rb) == 1);
  g_moqtrel_rb.subs[1].active = 1;
  CHECK(moqtrel_all_done(&g_moqtrel_rb) == 0);
  g_moqtrel_rb.subs[1].shed = 1;
  CHECK(moqtrel_all_done(&g_moqtrel_rb) == 1);
}

static void test_moqtrel_wraps_ring_end_many_times(void) {
  moqtrel_reset(&g_moqtrel_rb);
  g_moqtrel_rb.subs[0].active = 1;
  int ok                      = 1;
  while (g_moqtrel_rb.tail < 2 * WIRED_MOQTREL_CAP) {
    if (moqtrel_test_fill(1000) != 1) ok = 0;
    for (;;) {
      wired_span r   = moqtrel_next_round(&g_moqtrel_rb, 0);
      u64        off = g_moqtrel_rb.subs[0].sent;
      if (r.n == 0) break;
      if (r.p != g_moqtrel_rb.buf + off % WIRED_MOQTREL_CAP) ok = 0;
      for (usz i = 0; i < r.n; i++)
        if (r.p[i] != (u8)((off + i) & 0xff)) ok = 0;
      moqtrel_note_sent(&g_moqtrel_rb, 0, r.n, 0);
    }
    moqtrel_reclaim(&g_moqtrel_rb);
  }
  CHECK(ok); /* every span contiguous, every byte in place, both laps */
  CHECK(g_moqtrel_rb.head == g_moqtrel_rb.tail);
  CHECK(g_moqtrel_rb.tail >= 2 * WIRED_MOQTREL_CAP);
}

void test_moqtrel(void) {
  test_moqtrel_append_hold_at_watermark();
  test_moqtrel_hold_leaves_room_for_window();
  test_moqtrel_append_full_reports_overflow();
  test_moqtrel_next_round_span_starts_at_cursor();
  test_moqtrel_next_round_capped_by_round_max();
  test_moqtrel_next_round_stops_at_ring_end();
  test_moqtrel_note_sent_advances_cursor();
  test_moqtrel_reclaim_follows_slowest();
  test_moqtrel_reclaim_skips_abandoned_sub();
  test_moqtrel_reclaim_skips_detached_sub();
  test_moqtrel_release_at_low_watermark();
  test_moqtrel_stalled_after_timeout();
  test_moqtrel_all_done_when_subs_finish();
  test_moqtrel_wraps_ring_end_many_times();
}
