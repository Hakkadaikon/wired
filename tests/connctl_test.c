#include "test.h"

static void test_new_token_with_token(void)
{
    u8 tok[5] = {0x11, 0x22, 0x33, 0x44, 0x55};
    quic_new_token_frame in = {.length = 5, .token = tok};
    u8 buf[64];
    usz w = quic_new_token_encode(buf, sizeof(buf), &in);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_NEW_TOKEN);

    quic_new_token_frame out;
    usz r = quic_new_token_decode(buf, w, &out);
    CHECK(r == w && out.length == 5);
    CHECK(out.token[0] == 0x11 && out.token[4] == 0x55);

    CHECK(quic_new_token_decode(buf, w - 1, &out) == 0); /* token cut short */
}

static void test_new_token_empty(void)
{
    quic_new_token_frame in = {.length = 0, .token = 0};
    u8 buf[64];
    usz w = quic_new_token_encode(buf, sizeof(buf), &in);
    CHECK(w == 2 && buf[0] == QUIC_FRAME_NEW_TOKEN);

    quic_new_token_frame out;
    CHECK(quic_new_token_decode(buf, w, &out) == w && out.length == 0);
}

static void test_retire_cid(void)
{
    u8 buf[16];
    usz w = quic_retire_cid_encode(buf, sizeof(buf), 0x3FFF);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_RETIRE_CID);

    u64 seq;
    CHECK(quic_retire_cid_decode(buf, w, &seq) == w && seq == 0x3FFF);
    CHECK(quic_retire_cid_decode(buf, 1, &seq) == 0); /* seq varint cut */
}

static void test_connctl_path(void)
{
    u8 data[QUIC_PATH_DATA] = {1, 2, 3, 4, 5, 6, 7, 8};
    u8 buf[16];
    usz w = quic_path_encode(buf, sizeof(buf), QUIC_FRAME_PATH_CHALLENGE, data);
    CHECK(w == 9 && buf[0] == QUIC_FRAME_PATH_CHALLENGE);

    u8 out[QUIC_PATH_DATA];
    usz r = quic_path_decode(buf, w, QUIC_FRAME_PATH_CHALLENGE, out);
    CHECK(r == w && out[0] == 1 && out[7] == 8);

    /* PATH_RESPONSE shares the codec, type only differs */
    usz wr = quic_path_encode(buf, sizeof(buf), QUIC_FRAME_PATH_RESPONSE, data);
    CHECK(wr == 9 && buf[0] == QUIC_FRAME_PATH_RESPONSE);
    CHECK(quic_path_decode(buf, wr, QUIC_FRAME_PATH_RESPONSE, out) == wr);

    /* wrong type and truncation both reject */
    CHECK(quic_path_decode(buf, wr, QUIC_FRAME_PATH_CHALLENGE, out) == 0);
    CHECK(quic_path_decode(buf, w - 1, QUIC_FRAME_PATH_CHALLENGE, out) == 0);
}

static void test_handshake_done(void)
{
    u8 buf[4];
    usz w = quic_handshake_done_encode(buf, sizeof(buf));
    CHECK(w == 1 && buf[0] == QUIC_FRAME_HANDSHAKE_DONE);
    CHECK(quic_handshake_done_decode(buf, w) == 1);

    u8 wrong[1] = {0x00};
    CHECK(quic_handshake_done_decode(wrong, 1) == 0);
    CHECK(quic_handshake_done_decode(buf, 0) == 0); /* empty input */
}

void test_connctl(void)
{
    test_new_token_with_token();
    test_new_token_empty();
    test_retire_cid();
    test_connctl_path();
    test_handshake_done();
}
