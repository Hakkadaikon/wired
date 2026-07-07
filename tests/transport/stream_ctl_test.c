#include "test.h"

/* RESET_STREAM round-trips and decode rejects truncated input. */
static void test_reset_stream(void) {
  quic_reset_stream_frame in = {
      .stream_id = 9, .error_code = 0x101, .final_size = 4096};
  u8  buf[32];
  usz w = quic_reset_stream_encode(buf, sizeof(buf), &in);
  CHECK(w != 0 && buf[0] == QUIC_FRAME_RESET_STREAM);

  quic_reset_stream_frame out;
  usz                     r = quic_reset_stream_decode(buf, w, &out);
  CHECK(r == w && out.stream_id == 9 && out.error_code == 0x101);
  CHECK(out.final_size == 4096);

  CHECK(quic_reset_stream_decode(buf, w - 1, &out) == 0);
}

/* STOP_SENDING round-trips and decode rejects truncated input. */
static void test_stop_sending(void) {
  quic_stop_sending_frame in = {.stream_id = 7, .error_code = 0x202};
  u8                      buf[32];
  usz                     w = quic_stop_sending_encode(buf, sizeof(buf), &in);
  CHECK(w != 0 && buf[0] == QUIC_FRAME_STOP_SENDING);

  quic_stop_sending_frame out;
  usz                     r = quic_stop_sending_decode(buf, w, &out);
  CHECK(r == w && out.stream_id == 7 && out.error_code == 0x202);

  CHECK(quic_stop_sending_decode(buf, w - 1, &out) == 0);
}

/* RESET_STREAM_AT round-trips, enforces reliable_size <= final_size on
 * both encode and decode, and rejects truncated input.
 * draft-ietf-quic-reliable-stream-reset. */
static void test_reset_stream_at(void) {
  quic_reset_stream_at_frame in = {
      .stream_id     = 9,
      .error_code    = 0x101,
      .final_size    = 4096,
      .reliable_size = 100};
  u8  buf[32];
  usz w = quic_reset_stream_at_encode(buf, sizeof(buf), &in);
  CHECK(w != 0 && buf[0] == QUIC_FRAME_RESET_STREAM_AT);

  quic_reset_stream_at_frame out;
  usz                        r = quic_reset_stream_at_decode(buf, w, &out);
  CHECK(r == w && out.stream_id == 9 && out.error_code == 0x101);
  CHECK(out.final_size == 4096 && out.reliable_size == 100);

  CHECK(quic_reset_stream_at_decode(buf, w - 1, &out) == 0);

  /* boundary: reliable_size == final_size */
  in.reliable_size = in.final_size;
  w                = quic_reset_stream_at_encode(buf, sizeof(buf), &in);
  CHECK(w != 0);
  CHECK(quic_reset_stream_at_decode(buf, w, &out) == w);
  CHECK(out.reliable_size == out.final_size);

  /* boundary: reliable_size == 0 */
  in.reliable_size = 0;
  w                = quic_reset_stream_at_encode(buf, sizeof(buf), &in);
  CHECK(w != 0);
  CHECK(quic_reset_stream_at_decode(buf, w, &out) == w);
  CHECK(out.reliable_size == 0);

  /* reject: reliable_size > final_size, refused by encode */
  in.reliable_size = in.final_size + 1;
  CHECK(quic_reset_stream_at_encode(buf, sizeof(buf), &in) == 0);

  /* reject: hand-crafted wire bytes with reliable_size > final_size must
   * also be rejected by decode (receiver-side FRAME_ENCODING_ERROR).
   * final_size=50 and reliable_size=10 both fit a 1-byte varint (prefix
   * 00, value <= 0x3F); corrupting the trailing byte to 0x3F (63) keeps
   * it a valid-length 1-byte varint but 63 > 50. */
  in.final_size    = 50;
  in.reliable_size = 10;
  w                = quic_reset_stream_at_encode(buf, sizeof(buf), &in);
  CHECK(w != 0);
  buf[w - 1] = 0x3F;
  CHECK(quic_reset_stream_at_decode(buf, w, &out) == 0);
}

void test_stream_ctl(void) {
  test_reset_stream();
  test_stop_sending();
  test_reset_stream_at();
}
