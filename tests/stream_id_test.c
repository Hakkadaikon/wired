#include "test.h"
#include "stream/stream_id.c"

/* RFC 9000 2.1: the four type bit patterns. */
static void test_stream_id_types(void)
{
    /* 0x0 client bidi, 0x1 server bidi, 0x2 client uni, 0x3 server uni */
    CHECK(quic_stream_is_client_initiated(0) == 1 && quic_stream_is_uni(0) == 0);
    CHECK(quic_stream_is_client_initiated(1) == 0 && quic_stream_is_uni(1) == 0);
    CHECK(quic_stream_is_client_initiated(2) == 1 && quic_stream_is_uni(2) == 1);
    CHECK(quic_stream_is_client_initiated(3) == 0 && quic_stream_is_uni(3) == 1);
}

/* Constructing an id then reading its type and index round-trips. */
static void test_stream_id_construct(void)
{
    /* first client bidi stream is 0; first server uni is 3 */
    CHECK(quic_stream_id(0, 0, 0) == 0);
    CHECK(quic_stream_id(1, 1, 0) == 3);
    /* index 5, server, uni: (5<<2)|3 = 23 */
    u64 id = quic_stream_id(1, 1, 5);
    CHECK(id == 23);
    CHECK(quic_stream_is_client_initiated(id) == 0 && quic_stream_is_uni(id) == 1);
    /* the next client bidi after stream 0 is stream 4 */
    CHECK(quic_stream_id(0, 0, 1) == 4);
}

void test_stream_id(void)
{
    test_stream_id_types();
    test_stream_id_construct();
}
