#include "test.h"

/* Local nul-terminated string compare; src/ has no libc strcmp. */
static int qlogevent_streq(const char* a, const char* b) {
  usz i = 0;
  for (; a[i] || b[i]; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

/* wired_qlogevent_* build a single-line JSON record text for a given qlog
 * event kind, using known time/packet-number/byte-count inputs and comparing
 * against the exact expected JSON string. Every record carries a group_id
 * (the server's connection slot) right after time: a multi-connection
 * server appends every connection's records into ONE qlog file, and without
 * per-record attribution a 4-client room's packet/metrics streams interleave
 * indistinguishably (observed live -- the mixed stream was undiagnosable). */

static void test_qlogevent_packet_sent(void) {
  char out[128] = {0};
  usz  n        = wired_qlogevent_packet_sent(out, sizeof out, 42, 3, 7, 1200);
  CHECK(qlogevent_streq(
      out,
      "{\"time\":42,\"group_id\":3,\"name\":\"packet_sent\",\"pn\":7,"
      "\"bytes\":1200}"));
  CHECK(n == 65);
}

static void test_qlogevent_packet_received(void) {
  char out[128] = {0};
  usz  n = wired_qlogevent_packet_received(out, sizeof out, 100, 0, 3, 55);
  CHECK(qlogevent_streq(
      out,
      "{\"time\":100,\"group_id\":0,\"name\":\"packet_received\",\"pn\":3,"
      "\"bytes\":55}"));
  CHECK(n == 68);
}

static void test_qlogevent_packet_lost(void) {
  char out[128] = {0};
  usz  n        = wired_qlogevent_packet_lost(out, sizeof out, 5, 1, 9);
  CHECK(qlogevent_streq(
      out, "{\"time\":5,\"group_id\":1,\"name\":\"packet_lost\",\"pn\":9}"));
  CHECK(n == 51);
}

static void test_qlogevent_conn_state(void) {
  char out[128] = {0};
  usz  n        = wired_qlogevent_conn_state(out, sizeof out, 1, 2, "closed");
  CHECK(qlogevent_streq(
      out,
      "{\"time\":1,\"group_id\":2,\"name\":\"connection_state_updated\","
      "\"state\":\"closed\"}"));
  CHECK(n == 74);
}

static void test_qlogevent_metrics(void) {
  char                       out[256] = {0};
  wired_qlogevent_metrics_in m        = {30000, 14720, 2400, 500, 12, 3, 7, 2};
  usz n = wired_qlogevent_metrics(out, sizeof out, 1234, 3, &m);
  CHECK(n != 0);
  CHECK(qlogevent_streq(
      out,
      "{\"time\":1234,\"group_id\":3,\"name\":\"recovery:metrics_updated\","
      "\"smoothed_rtt\":30000,\"cwnd\":14720,\"bytes_in_flight\":2400,"
      "\"wtsend_ok\":500,\"wtsend_busy\":12,\"wtsend_flow\":3,"
      "\"wtwin_drop\":7,\"streams_blocked\":2}"));
}

/* stream_frame is a generic builder: `name` picks the event kind so the sent
 * and lost variants share one code path (fields are identical). */
static void test_qlogevent_stream_frame_sent(void) {
  char                            out[192] = {0};
  wired_qlogevent_stream_frame_in f        = {7, 1200, 350, 0, 42};
  usz                             n        = wired_qlogevent_stream_frame(
      out, sizeof out, 500, 3, "stream_frame_sent", &f);
  CHECK(qlogevent_streq(
      out,
      "{\"time\":500,\"group_id\":3,\"name\":\"stream_frame_sent\","
      "\"stream_id\":7,\"offset\":1200,\"length\":350,\"fin\":0,"
      "\"pn\":42}"));
  CHECK(n != 0);
}

/* Same builder, different name and a fin=1 boundary value -- proves the
 * builder is reusable for the loss variant without new code. */
static void test_qlogevent_stream_frame_lost(void) {
  char                            out[192] = {0};
  wired_qlogevent_stream_frame_in f        = {9, 0, 19, 1, 100};
  usz                             n        = wired_qlogevent_stream_frame(
      out, sizeof out, 600, 1, "stream_frame_lost", &f);
  CHECK(qlogevent_streq(
      out,
      "{\"time\":600,\"group_id\":1,\"name\":\"stream_frame_lost\","
      "\"stream_id\":9,\"offset\":0,\"length\":19,\"fin\":1,"
      "\"pn\":100}"));
  CHECK(n != 0);
}

/* Buffer too small for the fully-built record: rejected, no partial write
 * claimed via a nonzero return. */
static void test_qlogevent_buffer_too_small(void) {
  char                            out[8];
  wired_qlogevent_metrics_in      m  = {0};
  wired_qlogevent_stream_frame_in sf = {0};
  CHECK(wired_qlogevent_packet_sent(out, sizeof out, 42, 0, 7, 1200) == 0);
  CHECK(wired_qlogevent_packet_received(out, sizeof out, 100, 0, 3, 55) == 0);
  CHECK(wired_qlogevent_packet_lost(out, sizeof out, 5, 0, 9) == 0);
  CHECK(wired_qlogevent_conn_state(out, sizeof out, 1, 0, "closed") == 0);
  CHECK(wired_qlogevent_metrics(out, sizeof out, 1, 0, &m) == 0);
  CHECK(wired_qlogevent_stream_frame(out, sizeof out, 1, 0, "x", &sf) == 0);
}

void test_qlogevent(void) {
  test_qlogevent_packet_sent();
  test_qlogevent_packet_received();
  test_qlogevent_packet_lost();
  test_qlogevent_conn_state();
  test_qlogevent_metrics();
  test_qlogevent_stream_frame_sent();
  test_qlogevent_stream_frame_lost();
  test_qlogevent_buffer_too_small();
}
