#include "test.h"

static void test_credit_consume_slides(void) {
  flow_credit c;
  flow_credit_init(&c, 1000);
  CHECK(c.max_data == 1000);
  CHECK(flow_credit_consume(&c, 400) == 1400); /* limit slides forward */
  CHECK(flow_credit_consume(&c, 100) == 1500);
}

static void test_credit_violation(void) {
  flow_credit c;
  flow_credit_init(&c, 1000);
  CHECK(flow_credit_violation(&c, 1000) == 0); /* exactly at limit */
  CHECK(flow_credit_violation(&c, 999) == 0);
  CHECK(flow_credit_violation(&c, 1001) == 1); /* over the limit */

  /* after consuming, the higher limit permits more received bytes */
  flow_credit_consume(&c, 500);
  CHECK(flow_credit_violation(&c, 1500) == 0);
  CHECK(flow_credit_violation(&c, 1501) == 1);
}

void test_credit(void) {
  test_credit_consume_slides();
  test_credit_violation();
}
