#include "test.h"

/* The setting values are returned verbatim. */
static void test_qpack_settings_value(void)
{
    CHECK(quic_h3_qpack_max_table(4096) == 4096);
    CHECK(quic_h3_qpack_blocked_streams(16) == 16);
}

/* An omitted parameter defaults to 0. */
static void test_qpack_settings_default(void)
{
    CHECK(quic_h3_qpack_max_table(0) == 0);
    CHECK(quic_h3_qpack_blocked_streams(0) == 0);
}

/* The identifiers match RFC 9204 5. */
static void test_qpack_settings_ids(void)
{
    CHECK(QUIC_H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY == 0x01);
    CHECK(QUIC_H3_SETTINGS_QPACK_BLOCKED_STREAMS == 0x07);
}

void test_qpack_settings(void)
{
    test_qpack_settings_value();
    test_qpack_settings_default();
    test_qpack_settings_ids();
}
