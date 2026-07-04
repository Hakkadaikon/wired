#include "common/platform/clock/clock.h"

#include "test.h"

/* Golden pairs generated independently with Python
 * datetime.fromtimestamp(x, tz=UTC): epoch 0, both sides of the 2000-02-29
 * (/400 rule) boundary, the 2020 leap-day rollover, the 2100 non-leap
 * (/100 rule) rollover, and a mid-range 2026 value. */
static void test_clock_vectors(void) {
  static const u64 v[][2] = {
      {0ULL, 19700101000000ULL},          {951782399ULL, 20000228235959ULL},
      {951782400ULL, 20000229000000ULL},  {1583020799ULL, 20200229235959ULL},
      {1583020800ULL, 20200301000000ULL}, {4107542399ULL, 21000228235959ULL},
      {4107542400ULL, 21000301000000ULL}, {1782988200ULL, 20260702103000ULL},
      {1798761599ULL, 20261231235959ULL}, {1798761600ULL, 20270101000000ULL},
  };
  for (usz i = 0; i < sizeof(v) / sizeof(v[0]); i++)
    CHECK(quic_clock_epoch_to_ymdhms(v[i][0]) == v[i][1]);
}

/* The live wall clock lands in a sane window (this SDK ships in 2026+). */
static void test_clock_live(void) {
  u64 now = quic_clock_ymdhms();
  CHECK(now >= 20260101000000ULL && now < 21000101000000ULL);
}

/* The monotonic clock ticks: nonzero on a live system, never decreasing. */
static void test_clock_mono(void) {
  u64 a = quic_clock_mono_ms();
  u64 b = quic_clock_mono_ms();
  CHECK(a != 0);
  CHECK(b >= a);
}

void test_clock(void) {
  test_clock_vectors();
  test_clock_live();
  test_clock_mono();
}
