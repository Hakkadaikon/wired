#include "transport/packet/frame/pipeline/framewalk.h"

#include "test.h"
#include "transport/packet/frame/frame/frame.h"

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

void test_framewalk(void) {
  test_framewalk_sequence();
  test_framewalk_unmeasurable();
}
