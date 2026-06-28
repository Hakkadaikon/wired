#include "test.h"

/* RFC 9114 6.2.1: control stream prefix is the single byte 0x00. */
void test_h3settings_control_open(void)
{
    u8 buf[4];
    usz n = 0;
    CHECK(quic_h3settings_control_prefix(buf, sizeof(buf), &n) == 1);
    CHECK(n == 1 && buf[0] == QUIC_H3_STREAM_CONTROL);

    /* parses back as a control stream type */
    u64 type;
    usz consumed = 0;
    CHECK(quic_h3_stream_type_parse(buf, n, &type, &consumed) == 1);
    CHECK(consumed == 1 && quic_h3_stream_type_is_control(type));

    /* no room */
    CHECK(quic_h3settings_control_prefix(buf, 0, &n) == 0);
}
