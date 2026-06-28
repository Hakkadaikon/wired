#include "test.h"

/* RFC 9114 6.2.1: control stream opens with type 0x00 then a SETTINGS frame
 * that satisfies the "first frame MUST be SETTINGS" rule. */
void test_h3settings_control_settings(void)
{
    u8 buf[64];
    usz n = 0;
    CHECK(quic_h3settings_control_stream(buf, sizeof(buf), &n) == 1);

    /* leading stream type is control */
    u64 stype;
    usz consumed = 0;
    CHECK(quic_h3_stream_type_parse(buf, n, &stype, &consumed) == 1);
    CHECK(consumed == 1 && quic_h3_stream_type_is_control(stype));

    /* the bytes after the type are a SETTINGS frame */
    u64 ftype, plen;
    const u8 *pl;
    usz r = quic_h3_frame_get(buf + consumed, n - consumed, &ftype, &pl, &plen);
    CHECK(r == n - consumed && ftype == QUIC_H3_FRAME_SETTINGS);

    /* the first control frame passes the settings-sequence gate */
    quic_h3_settings_state st = {0};
    CHECK(quic_h3_settings_first(&st, ftype) == 1);

    /* no room */
    CHECK(quic_h3settings_control_stream(buf, 1, &n) == 0);
}
