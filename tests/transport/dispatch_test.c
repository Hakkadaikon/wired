#include "test.h"

static void test_dispatch_classify(void) {
  CHECK(quic_frame_classify(0x00) == QUIC_FK_PADDING);
  CHECK(quic_frame_classify(0x01) == QUIC_FK_PING);
  CHECK(quic_frame_classify(0x02) == QUIC_FK_ACK);
  CHECK(quic_frame_classify(0x03) == QUIC_FK_ACK);
  CHECK(quic_frame_classify(0x06) == QUIC_FK_CRYPTO);
  /* every STREAM type 0x08..0x0f maps to STREAM */
  for (u64 t = 0x08; t <= 0x0f; t++)
    CHECK(quic_frame_classify(t) == QUIC_FK_STREAM);
  CHECK(quic_frame_classify(0x12) == QUIC_FK_MAX_STREAMS);
  CHECK(quic_frame_classify(0x13) == QUIC_FK_MAX_STREAMS);
  CHECK(quic_frame_classify(0x1c) == QUIC_FK_CONNECTION_CLOSE);
  CHECK(quic_frame_classify(0x1d) == QUIC_FK_CONNECTION_CLOSE);
  CHECK(quic_frame_classify(0x1e) == QUIC_FK_HANDSHAKE_DONE);
  CHECK(quic_frame_classify(0x31) == QUIC_FK_DATAGRAM);
  /* undefined type -> UNKNOWN */
  CHECK(quic_frame_classify(0x99) == QUIC_FK_UNKNOWN);
  CHECK(quic_frame_classify(0x20) == QUIC_FK_UNKNOWN);
}

/* ACK, PADDING, CONNECTION_CLOSE are not ack-eliciting; others are. */
static void test_dispatch_ack_eliciting(void) {
  CHECK(quic_frame_ack_eliciting(QUIC_FK_PADDING) == 0);
  CHECK(quic_frame_ack_eliciting(QUIC_FK_ACK) == 0);
  CHECK(quic_frame_ack_eliciting(QUIC_FK_CONNECTION_CLOSE) == 0);
  CHECK(quic_frame_ack_eliciting(QUIC_FK_UNKNOWN) == 0);
  CHECK(quic_frame_ack_eliciting(QUIC_FK_PING) == 1);
  CHECK(quic_frame_ack_eliciting(QUIC_FK_STREAM) == 1);
  CHECK(quic_frame_ack_eliciting(QUIC_FK_CRYPTO) == 1);
  CHECK(quic_frame_ack_eliciting(QUIC_FK_HANDSHAKE_DONE) == 1);
}

/* RFC 9000 12.4: frame types are encoded on the shortest possible
 * variable-length integer. Every defined frame type value (dispatch.c's
 * TABLE) fits the 1-byte varint range (<= 0x3F, RFC 9000 16), so
 * quic_varint_len/quic_varint_encode must both settle on 1 byte for each. */
static void test_dispatch_frame_type_shortest_varint(void) {
  static const u64 types[] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
      0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x24, 0x30, 0x31};
  for (usz i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
    u8 buf[8];
    CHECK(quic_varint_len(types[i]) == 1);
    CHECK(quic_varint_encode(buf, types[i]) == 1 && buf[0] == types[i]);
  }
}

void test_dispatch(void) {
  test_dispatch_classify();
  test_dispatch_ack_eliciting();
  test_dispatch_frame_type_shortest_varint();
}
