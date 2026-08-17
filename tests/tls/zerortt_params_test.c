#include "test.h"

/* RFC 9001 4.6.2 */
void test_zerortt_params(void) {
  CHECK(zerortt_param_ok(100, 100) == 1); /* equal: ok */
  CHECK(zerortt_param_ok(100, 200) == 1); /* raised: ok */
  CHECK(zerortt_param_ok(100, 99) == 0);  /* lowered: reject */
  CHECK(zerortt_param_ok(0, 0) == 1);
}
