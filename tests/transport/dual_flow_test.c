#include "test.h"

void test_dual_flow(void) {
  CHECK(quic_dual_flow_ok(50, 100, 500, 1000) == 1);   /* both within */
  CHECK(quic_dual_flow_ok(100, 100, 1000, 1000) == 1); /* both at limit */
  CHECK(quic_dual_flow_ok(101, 100, 500, 1000) == 0);  /* stream over */
  CHECK(quic_dual_flow_ok(50, 100, 1001, 1000) == 0);  /* conn over */
  CHECK(quic_dual_flow_ok(101, 100, 1001, 1000) == 0); /* both over */
}
