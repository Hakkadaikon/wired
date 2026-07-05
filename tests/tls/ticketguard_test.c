#include "tls/keys/ticketguard/ticketguard.h"

#include "test.h"
#include "transport/conn/loop/manage/zerortt_policy.h"

/* A ticket passes exactly once: its second presentation is a replay, an
 * unrelated ticket still passes, and a blob too short to fingerprint is
 * refused outright. */
static void test_ticketguard_single_use(void) {
  quic_ticketguard g;
  u8               a[32] = {1}, b[32] = {2}, tiny[8] = {3};
  quic_ticketguard_init(&g);
  CHECK(quic_ticketguard_first_use(&g, quic_span_of(a, 32)) == 1);
  CHECK(quic_ticketguard_first_use(&g, quic_span_of(a, 32)) == 0);
  CHECK(quic_ticketguard_first_use(&g, quic_span_of(b, 32)) == 1);
  CHECK(quic_ticketguard_first_use(&g, quic_span_of(tiny, 8)) == 0);
}

/* The ring holds the last 64 fingerprints: pushing 64 fresh tickets evicts
 * the oldest, which then reads as first use again (the documented window
 * limit of the fixed ring). */
static void test_ticketguard_ring_window(void) {
  quic_ticketguard g;
  u8               t[32] = {0};
  quic_ticketguard_init(&g);
  t[0] = 0xEE;
  CHECK(quic_ticketguard_first_use(&g, quic_span_of(t, 32)) == 1);
  for (int i = 0; i < QUIC_TICKETGUARD_CAP; i++) {
    u8 fresh[32] = {0};
    fresh[0]     = (u8)i;
    fresh[1]     = 0x77;
    CHECK(quic_ticketguard_first_use(&g, quic_span_of(fresh, 32)) == 1);
  }
  t[0] = 0xEE; /* evicted by the 64 newer entries: passes again */
  CHECK(quic_ticketguard_first_use(&g, quic_span_of(t, 32)) == 1);
}

/* The accept rule: policy AND first use, never one alone. */
static void test_zerortt_accept_rule(void) {
  CHECK(quic_zerortt_replay_ok(1, 1) == 1);
  CHECK(quic_zerortt_replay_ok(1, 0) == 0);
  CHECK(quic_zerortt_replay_ok(0, 1) == 0);
  CHECK(quic_zerortt_replay_ok(0, 0) == 0);
}

void test_ticketguard(void) {
  test_ticketguard_single_use();
  test_ticketguard_ring_window();
  test_zerortt_accept_rule();
}
