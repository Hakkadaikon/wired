#include "test.h"

static void test_rtxstore_store_get_roundtrip(void)
{
    quic_rtxbytes st;
    const u8 frame[] = {0x08, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'};
    const u8 *got;
    usz len;

    quic_rtxbytes_init(&st);
    CHECK(quic_rtxbytes_store(&st, 7, frame, sizeof frame) == 1);
    CHECK(quic_rtxbytes_get(&st, 7, &got, &len) == 1);
    CHECK(len == sizeof frame);
    for (usz i = 0; i < sizeof frame; i++) CHECK(got[i] == frame[i]);
}

static void test_rtxstore_miss(void)
{
    quic_rtxbytes st;
    const u8 frame[] = {0x01};
    const u8 *got;
    usz len;

    quic_rtxbytes_init(&st);
    quic_rtxbytes_store(&st, 1, frame, sizeof frame);
    CHECK(quic_rtxbytes_get(&st, 99, &got, &len) == 0);
}

static void test_rtxstore_too_large(void)
{
    quic_rtxbytes st;
    static u8 big[QUIC_RTXBYTES_FRAME + 1];

    quic_rtxbytes_init(&st);
    CHECK(quic_rtxbytes_store(&st, 1, big, sizeof big) == 0);
}

void test_rtxstore(void)
{
    test_rtxstore_store_get_roundtrip();
    test_rtxstore_miss();
    test_rtxstore_too_large();
}
