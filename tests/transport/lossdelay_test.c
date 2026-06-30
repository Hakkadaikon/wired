#include "test.h"

/* 9/8 multiplier on the larger of srtt and latest_rtt. */
static void test_loss_delay_nine_eighths(void) {
  /* max(8000,8000)*9/8 = 9000, above granularity 1000 */
  CHECK(quic_lossdrive_loss_delay(8000, 8000, 1000) == 9000);
  /* uses the larger rtt: max(4000,8000)=8000 -> 9000 */
  CHECK(quic_lossdrive_loss_delay(4000, 8000, 1000) == 9000);
}

/* Granularity is the lower bound when 9/8*rtt is smaller. */
static void test_loss_delay_granularity_floor(void) {
  /* max(0,0)*9/8 = 0 -> clamped up to granularity 1000 */
  CHECK(quic_lossdrive_loss_delay(0, 0, 1000) == 1000);
  /* 500*9/8 = 562 < 1000 -> 1000 */
  CHECK(quic_lossdrive_loss_delay(500, 500, 1000) == 1000);
}

void test_lossdelay(void) {
  test_loss_delay_nine_eighths();
  test_loss_delay_granularity_floor();
}
