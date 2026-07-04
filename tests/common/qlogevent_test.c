#include "test.h"

/* Local nul-terminated string compare; src/ has no libc strcmp. */
static int qlogevent_streq(const char *a, const char *b) {
  usz i = 0;
  for (; a[i] || b[i]; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

/* wired_qlogevent_* build a single-line JSON record text for a given qlog
 * event kind, using known time/packet-number/byte-count inputs and comparing
 * against the exact expected JSON string. */

static void test_qlogevent_packet_sent(void) {
  char out[128] = {0};
  usz  n = wired_qlogevent_packet_sent(out, sizeof out, 42, 7, 1200);
  CHECK(n == 52);
  CHECK(qlogevent_streq(
      out,
      "{\"time\":42,\"name\":\"packet_sent\",\"pn\":7,\"bytes\":1200}"));
}

static void test_qlogevent_packet_received(void) {
  char out[128] = {0};
  usz  n = wired_qlogevent_packet_received(out, sizeof out, 100, 3, 55);
  CHECK(n == 55);
  CHECK(qlogevent_streq(
      out,
      "{\"time\":100,\"name\":\"packet_received\",\"pn\":3,\"bytes\":55}"));
}

static void test_qlogevent_packet_lost(void) {
  char out[128] = {0};
  usz  n = wired_qlogevent_packet_lost(out, sizeof out, 5, 9);
  CHECK(n == 38);
  CHECK(qlogevent_streq(
      out, "{\"time\":5,\"name\":\"packet_lost\",\"pn\":9}"));
}

static void test_qlogevent_conn_state(void) {
  char out[128] = {0};
  usz  n = wired_qlogevent_conn_state(out, sizeof out, 1, "closed");
  CHECK(n == 61);
  CHECK(qlogevent_streq(
      out,
      "{\"time\":1,\"name\":\"connection_state_updated\",\"state\":"
      "\"closed\"}"));
}

/* Buffer too small for the fully-built record: rejected, no partial write
 * claimed via a nonzero return. */
static void test_qlogevent_buffer_too_small(void) {
  char out[8];
  CHECK(wired_qlogevent_packet_sent(out, sizeof out, 42, 7, 1200) == 0);
  CHECK(wired_qlogevent_packet_received(out, sizeof out, 100, 3, 55) == 0);
  CHECK(wired_qlogevent_packet_lost(out, sizeof out, 5, 9) == 0);
  CHECK(wired_qlogevent_conn_state(out, sizeof out, 1, "closed") == 0);
}

void test_qlogevent(void) {
  test_qlogevent_packet_sent();
  test_qlogevent_packet_received();
  test_qlogevent_packet_lost();
  test_qlogevent_conn_state();
  test_qlogevent_buffer_too_small();
}
