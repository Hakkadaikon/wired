#include "test.h"

/* With the default exponent 3, the field value scales down by 8. */
static void test_ackdelay(void) {
  /* 1000 us / 8 = 125 */
  CHECK(ack_delay_encode(1000, 3) == 125);

  /* a non-default exponent */
  CHECK(ack_delay_encode(4096, 10) == 4);

  /* low bits below the exponent are truncated, as the field is coarse */
  CHECK(ack_delay_encode(1007, 3) == 125); /* 1007>>3 = 125 */
}
