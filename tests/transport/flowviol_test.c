#include "transport/stream/flow/flowviol/flowviol.h"

#include "common/diag/error/codes.h"
#include "test.h"

static void test_flowviol_data_overrun(void) {
  u64 ec = 0xff;
  /* received 1001 > max_data 1000 -> FLOW_CONTROL_ERROR */
  CHECK(
      quic_flowviol_check(
          &(quic_flow_usage){1001, 1000}, &(quic_flow_usage){0, 100}, &ec) ==
      1);
  CHECK(ec == QUIC_EC_FLOW_CONTROL_ERROR);
}

static void test_flowviol_stream_limit(void) {
  u64 ec = 0xff;
  /* count 3 against max_streams 3: a further open is over the limit */
  CHECK(
      quic_flowviol_check(
          &(quic_flow_usage){0, 1000}, &(quic_flow_usage){3, 3}, &ec) == 1);
  CHECK(ec == QUIC_EC_STREAM_LIMIT_ERROR);
}

static void test_flowviol_none(void) {
  u64 ec = 0xff;
  CHECK(
      quic_flowviol_check(
          &(quic_flow_usage){1000, 1000}, &(quic_flow_usage){2, 3}, &ec) ==
      0);            /* both within */
  CHECK(ec == 0xff); /* left untouched */
}

static void test_flowviol_data_before_streams(void) {
  u64 ec = 0;
  /* both over: connection-level data wins -> FLOW_CONTROL_ERROR */
  CHECK(
      quic_flowviol_check(
          &(quic_flow_usage){2000, 1000}, &(quic_flow_usage){5, 3}, &ec) == 1);
  CHECK(ec == QUIC_EC_FLOW_CONTROL_ERROR);
}

void test_flowviol(void) {
  test_flowviol_data_overrun();
  test_flowviol_stream_limit();
  test_flowviol_none();
  test_flowviol_data_before_streams();
}
