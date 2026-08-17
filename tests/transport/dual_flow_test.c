#include "test.h"

void test_dual_flow(void) {
  CHECK(
      dual_flow_ok(&(flow_usage){50, 100}, &(flow_usage){500, 1000}) ==
      1); /* both within */
  CHECK(
      dual_flow_ok(&(flow_usage){100, 100}, &(flow_usage){1000, 1000}) ==
      1); /* both at limit */
  CHECK(
      dual_flow_ok(&(flow_usage){101, 100}, &(flow_usage){500, 1000}) ==
      0); /* stream over */
  CHECK(
      dual_flow_ok(&(flow_usage){50, 100}, &(flow_usage){1001, 1000}) ==
      0); /* conn over */
  CHECK(
      dual_flow_ok(&(flow_usage){101, 100}, &(flow_usage){1001, 1000}) ==
      0); /* both over */
}
