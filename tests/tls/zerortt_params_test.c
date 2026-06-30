#include "test.h"

/* RFC 9001 4.6.2 */
void test_zerortt_params(void) {
  CHECK(quic_zerortt_param_ok(100, 100) == 1); /* equal: ok */
  CHECK(quic_zerortt_param_ok(100, 200) == 1); /* raised: ok */
  CHECK(quic_zerortt_param_ok(100, 99) == 0);  /* lowered: reject */
  CHECK(quic_zerortt_param_ok(0, 0) == 1);
}
