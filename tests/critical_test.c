#include "test.h"

/* Control, QPACK encoder and QPACK decoder streams are critical; push is not. */
static void test_critical_classify(void)
{
    CHECK(quic_h3_stream_is_critical(QUIC_H3_STREAM_CONTROL) == 1);
    CHECK(quic_h3_stream_is_critical(QUIC_H3_STREAM_QPACK_ENCODER) == 1);
    CHECK(quic_h3_stream_is_critical(QUIC_H3_STREAM_QPACK_DECODER) == 1);
    CHECK(quic_h3_stream_is_critical(QUIC_H3_STREAM_PUSH) == 0);
    CHECK(quic_h3_stream_is_critical(0x21) == 0); /* reserved/grease */
}

/* Closing a critical stream maps to H3_CLOSED_CRITICAL_STREAM; else no error. */
static void test_critical_close_error(void)
{
    CHECK(quic_h3_critical_close_error(QUIC_H3_STREAM_CONTROL)
          == QUIC_H3_CLOSED_CRITICAL_STREAM);
    CHECK(quic_h3_critical_close_error(QUIC_H3_STREAM_QPACK_DECODER)
          == QUIC_H3_CLOSED_CRITICAL_STREAM);
    CHECK(quic_h3_critical_close_error(QUIC_H3_STREAM_PUSH) == 0);
}

void test_critical(void)
{
    test_critical_classify();
    test_critical_close_error();
}
