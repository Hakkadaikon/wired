#include "test.h"

/* Build a 0x31 frame, then extract its payload as a view round-trips. */
void test_dg_recv_with_length(void)
{
    const u8 data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    u8 frame[16];
    usz w = 0;
    quic_dgdeliver_frame(data, 4, 1, 64, frame, sizeof(frame), &w);

    const u8 *p = 0;
    usz pl = 0;
    int ok = quic_dgdeliver_extract(frame, w, &p, &pl);
    CHECK(ok == 1 && pl == 4 && p == frame + 2); /* type + len byte */
    CHECK(p[0] == 0xDE && p[3] == 0xEF);
}

/* A 0x30 frame's payload is everything after the type byte. */
void test_dg_recv_no_length(void)
{
    const u8 data[] = {7, 8, 9};
    u8 frame[16];
    usz w = 0;
    quic_dgdeliver_frame(data, 3, 0, 64, frame, sizeof(frame), &w);

    const u8 *p = 0;
    usz pl = 0;
    int ok = quic_dgdeliver_extract(frame, w, &p, &pl);
    CHECK(ok == 1 && pl == 3 && p == frame + 1 && p[0] == 7 && p[2] == 9);
}

/* A truncated 0x31 frame (length claims more than is present) is rejected. */
void test_dg_recv_truncated(void)
{
    const u8 data[] = {1, 2, 3, 4, 5};
    u8 frame[16];
    usz w = 0;
    quic_dgdeliver_frame(data, 5, 1, 64, frame, sizeof(frame), &w);

    const u8 *p = 0;
    usz pl = 0;
    CHECK(quic_dgdeliver_extract(frame, w - 1, &p, &pl) == 0);
}
