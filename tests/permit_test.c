#include "test.h"

/* RFC 9000 12.4 Table 3 spot checks. */
static void test_permit_matrix(void)
{
    /* PADDING/PING permitted everywhere */
    CHECK(quic_frame_permitted(QUIC_FK_PADDING, QUIC_PKT_INITIAL) == 1);
    CHECK(quic_frame_permitted(QUIC_FK_PADDING, QUIC_PKT_1RTT) == 1);

    /* CRYPTO in Initial/Handshake/1-RTT but not 0-RTT */
    CHECK(quic_frame_permitted(QUIC_FK_CRYPTO, QUIC_PKT_INITIAL) == 1);
    CHECK(quic_frame_permitted(QUIC_FK_CRYPTO, QUIC_PKT_0RTT) == 0);

    /* ACK not allowed in 0-RTT */
    CHECK(quic_frame_permitted(QUIC_FK_ACK, QUIC_PKT_0RTT) == 0);
    CHECK(quic_frame_permitted(QUIC_FK_ACK, QUIC_PKT_HANDSHAKE) == 1);

    /* STREAM only in 0-RTT and 1-RTT */
    CHECK(quic_frame_permitted(QUIC_FK_STREAM, QUIC_PKT_INITIAL) == 0);
    CHECK(quic_frame_permitted(QUIC_FK_STREAM, QUIC_PKT_0RTT) == 1);
    CHECK(quic_frame_permitted(QUIC_FK_STREAM, QUIC_PKT_1RTT) == 1);

    /* HANDSHAKE_DONE only in 1-RTT */
    CHECK(quic_frame_permitted(QUIC_FK_HANDSHAKE_DONE, QUIC_PKT_1RTT) == 1);
    CHECK(quic_frame_permitted(QUIC_FK_HANDSHAKE_DONE, QUIC_PKT_HANDSHAKE) == 0);
}

/* GREASE frame types of the form 0x1f*N + 0x21 are recognized. */
static void test_permit_grease(void)
{
    CHECK(quic_frame_is_grease(0x21) == 1);        /* N=0 */
    CHECK(quic_frame_is_grease(0x21 + 0x1f) == 1); /* N=1 = 0x40 */
    CHECK(quic_frame_is_grease(0x20) == 0);        /* below the first point */
    CHECK(quic_frame_is_grease(0x08) == 0);        /* a real frame (STREAM) */
}

void test_permit(void)
{
    test_permit_matrix();
    test_permit_grease();
}
