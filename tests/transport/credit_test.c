#include "test.h"

static void test_credit_consume_slides(void) {
  quic_flow_credit c;
  quic_flow_credit_init(&c, 1000);
  CHECK(c.max_data == 1000);
  CHECK(quic_flow_credit_consume(&c, 400) == 1400); /* limit slides forward */
  CHECK(quic_flow_credit_consume(&c, 100) == 1500);
}

static void test_credit_violation(void) {
  quic_flow_credit c;
  quic_flow_credit_init(&c, 1000);
  CHECK(quic_flow_credit_violation(&c, 1000) == 0); /* exactly at limit */
  CHECK(quic_flow_credit_violation(&c, 999) == 0);
  CHECK(quic_flow_credit_violation(&c, 1001) == 1); /* over the limit */

  /* after consuming, the higher limit permits more received bytes */
  quic_flow_credit_consume(&c, 500);
  CHECK(quic_flow_credit_violation(&c, 1500) == 0);
  CHECK(quic_flow_credit_violation(&c, 1501) == 1);
}

void test_credit(void) {
  test_credit_consume_slides();
  test_credit_violation();
}
