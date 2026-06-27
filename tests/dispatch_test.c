#include "test.h"
#include "frame/dispatch.c"

static void test_dispatch_classify(void)
{
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
static void test_dispatch_ack_eliciting(void)
{
    CHECK(quic_frame_ack_eliciting(QUIC_FK_PADDING) == 0);
    CHECK(quic_frame_ack_eliciting(QUIC_FK_ACK) == 0);
    CHECK(quic_frame_ack_eliciting(QUIC_FK_CONNECTION_CLOSE) == 0);
    CHECK(quic_frame_ack_eliciting(QUIC_FK_UNKNOWN) == 0);
    CHECK(quic_frame_ack_eliciting(QUIC_FK_PING) == 1);
    CHECK(quic_frame_ack_eliciting(QUIC_FK_STREAM) == 1);
    CHECK(quic_frame_ack_eliciting(QUIC_FK_CRYPTO) == 1);
    CHECK(quic_frame_ack_eliciting(QUIC_FK_HANDSHAKE_DONE) == 1);
}

void test_dispatch(void)
{
    test_dispatch_classify();
    test_dispatch_ack_eliciting();
}
