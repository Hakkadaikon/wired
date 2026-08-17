#include "test.h"

/* RFC 9001 5.7: incoming 1-RTT packets must be deferred while the
 * handshake is not complete, and processed normally once it is. */
static void test_pending1rtt_should_defer(void) {
  CHECK(pending1rtt_should_defer(0));
  CHECK(!pending1rtt_should_defer(1));
}

static void test_pending1rtt_starts_empty(void) {
  pending1rtt q;
  pending1rtt_init(&q);
  CHECK(pending1rtt_count(&q) == 0);
}

static void test_pending1rtt_store_and_peek_fifo(void) {
  pending1rtt q;
  u8          a[3] = {1, 2, 3}, b[2] = {9, 8};
  const u8*   p;
  usz         n;
  pending1rtt_init(&q);
  CHECK(pending1rtt_store(&q, a, 3));
  CHECK(pending1rtt_store(&q, b, 2));
  CHECK(pending1rtt_count(&q) == 2);

  CHECK(pending1rtt_peek(&q, 0, &p, &n));
  CHECK(n == 3 && p[0] == 1 && p[1] == 2 && p[2] == 3);

  CHECK(pending1rtt_peek(&q, 1, &p, &n));
  CHECK(n == 2 && p[0] == 9 && p[1] == 8);

  CHECK(!pending1rtt_peek(&q, 2, &p, &n));
}

static void test_pending1rtt_rejects_oversized(void) {
  pending1rtt q;
  u8          big[PENDING1RTT_MAX_LEN + 1] = {0};
  pending1rtt_init(&q);
  CHECK(!pending1rtt_store(&q, big, sizeof(big)));
  CHECK(pending1rtt_count(&q) == 0);
}

static void test_pending1rtt_rejects_when_full(void) {
  pending1rtt q;
  u8          one[1] = {0};
  pending1rtt_init(&q);
  for (usz i = 0; i < PENDING1RTT_CAP; i++)
    CHECK(pending1rtt_store(&q, one, 1));
  CHECK(!pending1rtt_store(&q, one, 1));
  CHECK(pending1rtt_count(&q) == PENDING1RTT_CAP);
}

static void test_pending1rtt_clear(void) {
  pending1rtt q;
  u8          one[1] = {0};
  pending1rtt_init(&q);
  CHECK(pending1rtt_store(&q, one, 1));
  pending1rtt_clear(&q);
  CHECK(pending1rtt_count(&q) == 0);
}

void test_pending1rtt(void) {
  test_pending1rtt_should_defer();
  test_pending1rtt_starts_empty();
  test_pending1rtt_store_and_peek_fifo();
  test_pending1rtt_rejects_oversized();
  test_pending1rtt_rejects_when_full();
  test_pending1rtt_clear();
}
