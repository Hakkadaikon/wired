#include "test.h"

static void test_stream_credit_open_up_to_limit(void) {
  stream_credit s;
  stream_credit_init(&s, 2);
  CHECK(stream_credit_open(&s) == 1);
  CHECK(stream_credit_open(&s) == 1);
  CHECK(stream_credit_open(&s) == 0); /* limit reached */
  CHECK(s.count == 2);                /* rejected open did not count */
}

static void test_stream_credit_grant_raises(void) {
  stream_credit s;
  stream_credit_init(&s, 1);
  CHECK(stream_credit_open(&s) == 1);
  CHECK(stream_credit_open(&s) == 0);

  stream_credit_grant(&s, 3); /* MAX_STREAMS raises the ceiling */
  CHECK(stream_credit_open(&s) == 1);
  CHECK(stream_credit_open(&s) == 1);
  CHECK(stream_credit_open(&s) == 0);
}

static void test_stream_credit_grant_never_lowers(void) {
  stream_credit s;
  stream_credit_init(&s, 5);
  stream_credit_grant(&s, 2); /* smaller grant ignored */
  CHECK(s.max_streams == 5);
}

void test_stream_credit(void) {
  test_stream_credit_open_up_to_limit();
  test_stream_credit_grant_raises();
  test_stream_credit_grant_never_lowers();
}
