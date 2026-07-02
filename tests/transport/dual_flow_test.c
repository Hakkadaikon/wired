#include "test.h"

void test_dual_flow(void) {
  CHECK(
      quic_dual_flow_ok(
          &(quic_flow_usage){50, 100}, &(quic_flow_usage){500, 1000}) ==
      1); /* both within */
  CHECK(
      quic_dual_flow_ok(
          &(quic_flow_usage){100, 100}, &(quic_flow_usage){1000, 1000}) ==
      1); /* both at limit */
  CHECK(
      quic_dual_flow_ok(
          &(quic_flow_usage){101, 100}, &(quic_flow_usage){500, 1000}) ==
      0); /* stream over */
  CHECK(
      quic_dual_flow_ok(
          &(quic_flow_usage){50, 100}, &(quic_flow_usage){1001, 1000}) ==
      0); /* conn over */
  CHECK(
      quic_dual_flow_ok(
          &(quic_flow_usage){101, 100}, &(quic_flow_usage){1001, 1000}) ==
      0); /* both over */
}
