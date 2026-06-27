#include "test.h"

/* Type 0x31 round-trips with an explicit length. */
static void test_datagram_with_len(void)
{
    const u8 payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
    quic_datagram_frame in = {.length = 4, .data = payload};
    u8 buf[16];
    usz w = quic_datagram_encode(buf, sizeof(buf), &in, 1);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_DATAGRAM_LEN);

    quic_datagram_frame out;
    usz r = quic_datagram_decode(buf, w, &out);
    CHECK(r == w && out.length == 4 && out.data[0] == 0xDE && out.data[3] == 0xEF);
}

/* Type 0x30 has no length; decode consumes the rest of the buffer. */
static void test_datagram_no_len(void)
{
    const u8 payload[] = {1, 2, 3};
    quic_datagram_frame in = {.length = 3, .data = payload};
    u8 buf[16];
    usz w = quic_datagram_encode(buf, sizeof(buf), &in, 0);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_DATAGRAM && w == 4); /* type + 3 data */

    quic_datagram_frame out;
    usz r = quic_datagram_decode(buf, w, &out);
    CHECK(r == w && out.length == 3 && out.data[0] == 1 && out.data[2] == 3);
}

static void test_datagram_truncated(void)
{
    const u8 payload[] = {1, 2, 3, 4, 5};
    quic_datagram_frame in = {.length = 5, .data = payload};
    u8 buf[16];
    usz w = quic_datagram_encode(buf, sizeof(buf), &in, 1);
    quic_datagram_frame out;
    CHECK(quic_datagram_decode(buf, w - 1, &out) == 0); /* data cut short */
    /* empty datagram (length 0) is allowed */
    quic_datagram_frame e = {.length = 0, .data = payload};
    usz ew = quic_datagram_encode(buf, sizeof(buf), &e, 1);
    CHECK(quic_datagram_decode(buf, ew, &out) == ew && out.length == 0);
}

/* A datagram is allowed only when the peer advertised a nonzero limit that
 * the frame does not exceed. */
static void test_datagram_allowed(void)
{
    CHECK(quic_datagram_allowed(0, 10) == 0);      /* unsupported */
    CHECK(quic_datagram_allowed(1200, 1200) == 1); /* exactly the limit */
    CHECK(quic_datagram_allowed(1200, 1201) == 0); /* over the limit */
}

void test_datagram(void)
{
    test_datagram_with_len();
    test_datagram_no_len();
    test_datagram_truncated();
    test_datagram_allowed();
}
