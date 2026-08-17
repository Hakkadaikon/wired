#include "test.h"

/* RFC 9114 4.1: a request stream begins with HEADERS, not DATA. */
static void test_reqorder_leading(void) {
  h3req_order_state s;
  h3req_order_init(&s);
  CHECK(s == H3REQ_ORDER_START);

  h3req_order_init(&s);
  CHECK(h3req_order_accept(&s, H3_FRAME_HEADERS) == 1);
  CHECK(s == H3REQ_ORDER_HEADERS);

  h3req_order_init(&s);
  CHECK(h3req_order_accept(&s, H3_FRAME_DATA) == 0);
  CHECK(s == H3REQ_ORDER_START);
}

/* HEADERS -> DATA -> trailing HEADERS is the full allowed sequence. */
static void test_reqorder_full(void) {
  h3req_order_state s;
  h3req_order_init(&s);
  CHECK(h3req_order_accept(&s, H3_FRAME_HEADERS) == 1);
  CHECK(h3req_order_accept(&s, H3_FRAME_DATA) == 1);
  CHECK(h3req_order_accept(&s, H3_FRAME_DATA) == 1);
  CHECK(h3req_order_accept(&s, H3_FRAME_HEADERS) == 1);
  CHECK(s == H3REQ_ORDER_TRAILERS);
}

/* Nothing is allowed after the trailer; a third HEADERS is rejected. */
static void test_reqorder_after_trailer(void) {
  h3req_order_state s;
  h3req_order_init(&s);
  h3req_order_accept(&s, H3_FRAME_HEADERS);
  h3req_order_accept(&s, H3_FRAME_HEADERS);
  CHECK(h3req_order_accept(&s, H3_FRAME_DATA) == 0);
  CHECK(h3req_order_accept(&s, H3_FRAME_HEADERS) == 0);
  CHECK(s == H3REQ_ORDER_TRAILERS);
}

void test_reqorder(void) {
  test_reqorder_leading();
  test_reqorder_full();
  test_reqorder_after_trailer();
}
