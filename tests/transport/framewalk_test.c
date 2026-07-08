#include "transport/packet/frame/pipeline/framewalk.h"

#include "app/datagram/datagram/datagram.h"
#include "test.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/frame/stream_ctl.h"

/* RFC 9000 12.4: the walker yields each frame's type in order across a mix of
 * single-byte and length-bearing frames. */
static void test_framewalk_sequence(void) {
  u8  buf[64];
  usz n = 0;
  n += quic_frame_put_simple(buf + n, sizeof(buf) - n, QUIC_FRAME_PING);
  quic_crypto_frame cf = {.offset = 0, .length = 3, .data = (const u8*)"abc"};
  n += quic_frame_put_crypto(buf + n, sizeof(buf) - n, &cf);
  quic_stream_frame sf = {
      .stream_id = 4,
      .offset    = 0,
      .length    = 2,
      .data      = (const u8*)"hi",
      .fin       = 1};
  n += quic_frame_put_stream(buf + n, sizeof(buf) - n, &sf);
  n += quic_frame_put_simple(buf + n, sizeof(buf) - n, QUIC_FRAME_PADDING);

  quic_framewalk it;
  quic_framewalk_init(&it, buf, n);

  quic_framewalk_item fr;

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_PING && fr.start == buf && fr.remaining == n);

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_CRYPTO);

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK((fr.type & 0xf8) == QUIC_FRAME_STREAM_BASE);

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_PADDING);

  CHECK(quic_framewalk_next(&it, &fr) == 0);
}

/* An unmeasurable frame type stops the walk rather than misreading bytes. */
static void test_framewalk_unmeasurable(void) {
  u8             buf[1] = {0x10}; /* MAX_DATA: not in the measurable set */
  quic_framewalk it;
  quic_framewalk_init(&it, buf, sizeof(buf));
  quic_framewalk_item fr;
  CHECK(quic_framewalk_next(&it, &fr) == 0);
}

/* RFC 9221 5 regression: a 0x31 (explicit Length) DATAGRAM frame followed by
 * another frame must be measured correctly, so the walk continues to see the
 * second frame rather than truncating the rest of the packet. */
static void test_framewalk_datagram_len_then_ping(void) {
  u8                  buf[64];
  usz                 n  = 0;
  quic_datagram_frame df = {.length = 3, .data = (const u8*)"xyz"};
  n += quic_datagram_encode(quic_mspan_of(buf + n, sizeof(buf) - n), &df, 1);
  n += quic_frame_put_simple(buf + n, sizeof(buf) - n, QUIC_FRAME_PING);

  quic_framewalk it;
  quic_framewalk_init(&it, buf, n);
  quic_framewalk_item fr;

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_DATAGRAM_LEN);

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_PING);

  CHECK(quic_framewalk_next(&it, &fr) == 0);
}

/* RFC 9221 5: a 0x30 (no Length) DATAGRAM frame consumes the rest of the
 * packet, as it must be the last frame. */
static void test_framewalk_datagram_no_len_consumes_rest(void) {
  u8                  buf[64];
  usz                 n  = 0;
  quic_datagram_frame df = {.length = 5, .data = (const u8*)"hello"};
  n += quic_datagram_encode(quic_mspan_of(buf + n, sizeof(buf) - n), &df, 0);

  quic_framewalk it;
  quic_framewalk_init(&it, buf, n);
  quic_framewalk_item fr;

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_DATAGRAM);
  CHECK(fr.remaining == n);

  CHECK(quic_framewalk_next(&it, &fr) == 0);
}

/* RFC 9000 19.4/19.5, draft-ietf-quic-reliable-stream-reset: RESET_STREAM,
 * STOP_SENDING, and RESET_STREAM_AT must each be measured (not treated as
 * unmeasurable), so a payload coalescing one of them with a following frame
 * lets the walk continue instead of stopping — this was the RESET_STREAM/
 * STOP_SENDING gap WT-F-007 depended on closing. */
static void test_framewalk_reset_stream_then_ping(void) {
  u8                      buf[64];
  usz                     n  = 0;
  quic_reset_stream_frame rf = {
      .stream_id = 4, .error_code = 1, .final_size = 0};
  n += quic_reset_stream_encode(buf + n, sizeof(buf) - n, &rf);
  n += quic_frame_put_simple(buf + n, sizeof(buf) - n, QUIC_FRAME_PING);

  quic_framewalk it;
  quic_framewalk_init(&it, buf, n);
  quic_framewalk_item fr;

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_RESET_STREAM);

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_PING);

  CHECK(quic_framewalk_next(&it, &fr) == 0);
}

static void test_framewalk_stop_sending_then_ping(void) {
  u8                      buf[64];
  usz                     n  = 0;
  quic_stop_sending_frame sf = {.stream_id = 4, .error_code = 2};
  n += quic_stop_sending_encode(buf + n, sizeof(buf) - n, &sf);
  n += quic_frame_put_simple(buf + n, sizeof(buf) - n, QUIC_FRAME_PING);

  quic_framewalk it;
  quic_framewalk_init(&it, buf, n);
  quic_framewalk_item fr;

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_STOP_SENDING);

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_PING);

  CHECK(quic_framewalk_next(&it, &fr) == 0);
}

static void test_framewalk_reset_stream_at_then_ping(void) {
  u8                         buf[64];
  usz                        n  = 0;
  quic_reset_stream_at_frame rf = {
      .stream_id = 4, .error_code = 3, .final_size = 10, .reliable_size = 5};
  n += quic_reset_stream_at_encode(buf + n, sizeof(buf) - n, &rf);
  n += quic_frame_put_simple(buf + n, sizeof(buf) - n, QUIC_FRAME_PING);

  quic_framewalk it;
  quic_framewalk_init(&it, buf, n);
  quic_framewalk_item fr;

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_RESET_STREAM_AT);

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_PING);

  CHECK(quic_framewalk_next(&it, &fr) == 0);
}

void test_framewalk(void) {
  test_framewalk_sequence();
  test_framewalk_unmeasurable();
  test_framewalk_datagram_len_then_ping();
  test_framewalk_datagram_no_len_consumes_rest();
  test_framewalk_reset_stream_then_ping();
  test_framewalk_stop_sending_then_ping();
  test_framewalk_reset_stream_at_then_ping();
}
