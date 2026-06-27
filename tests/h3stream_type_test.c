#include "test.h"

/* Each of the four unidirectional stream types parses from its leading varint
 * and classifies correctly (RFC 9114 6.2). */
static void test_h3stream_type_parse(void)
{
    u8 buf[1];
    u64 type;
    usz used;

    buf[0] = QUIC_H3_STREAM_CONTROL;
    CHECK(quic_h3_stream_type_parse(buf, 1, &type, &used) == 1);
    CHECK(used == 1 && type == QUIC_H3_STREAM_CONTROL);
    CHECK(quic_h3_stream_type_is_control(type) && !quic_h3_stream_type_is_push(type));

    buf[0] = QUIC_H3_STREAM_PUSH;
    quic_h3_stream_type_parse(buf, 1, &type, &used);
    CHECK(quic_h3_stream_type_is_push(type) && !quic_h3_stream_type_is_qpack(type));

    buf[0] = QUIC_H3_STREAM_QPACK_ENCODER;
    quic_h3_stream_type_parse(buf, 1, &type, &used);
    CHECK(quic_h3_stream_type_is_qpack(type) && !quic_h3_stream_type_is_control(type));

    buf[0] = QUIC_H3_STREAM_QPACK_DECODER;
    quic_h3_stream_type_parse(buf, 1, &type, &used);
    CHECK(quic_h3_stream_type_is_qpack(type));
}

/* A multi-byte varint stream type is read whole; an empty buffer is rejected. */
static void test_h3stream_type_varint(void)
{
    /* 0x4040 = two-byte varint for 0x40. */
    u8 buf[2] = {0x40, 0x40};
    u64 type;
    usz used;
    CHECK(quic_h3_stream_type_parse(buf, 2, &type, &used) == 1);
    CHECK(used == 2 && type == 0x40);

    CHECK(quic_h3_stream_type_parse(buf, 0, &type, &used) == 0);
}

void test_h3stream_type(void)
{
    test_h3stream_type_parse();
    test_h3stream_type_varint();
}
