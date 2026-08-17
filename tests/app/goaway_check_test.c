#include "test.h"

/* Server GOAWAY: only client-initiated bidi Stream IDs (id % 4 == 0). */
static void test_server_bidi(void) {
  CHECK(h3_goaway_id_ok(0, 1) == 1);
  CHECK(h3_goaway_id_ok(4, 1) == 1);
  CHECK(h3_goaway_id_ok(400, 1) == 1);
  CHECK(h3_goaway_id_ok(1, 1) == 0); /* client uni */
  CHECK(h3_goaway_id_ok(2, 1) == 0); /* server bidi */
  CHECK(h3_goaway_id_ok(3, 1) == 0); /* server uni */
}

/* Client GOAWAY: any Push ID is acceptable, including ones with low bits set.
 */
static void test_client_push_id(void) {
  CHECK(h3_goaway_id_ok(0, 0) == 1);
  CHECK(h3_goaway_id_ok(1, 0) == 1);
  CHECK(h3_goaway_id_ok(2, 0) == 1);
  CHECK(h3_goaway_id_ok(3, 0) == 1);
  CHECK(h3_goaway_id_ok(0xffffffffffffffffUL, 0) == 1);
}

void test_goaway_check(void) {
  test_server_bidi();
  test_client_push_id();
}
