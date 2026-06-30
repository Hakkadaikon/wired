#include "test.h"
#include "tls/handshake/core/tls/transcript_stage.h"

static int ts_digest_eq(const u8 *got, const char *hex)
{
    for (usz i = 0; i < QUIC_SHA256_DIGEST; i++) {
        u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
        u8 b = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                    (lo <= '9' ? lo - '0' : lo - 'a' + 10));
        if (got[i] != b) return 0;
    }
    return 1;
}

/* Stage helpers snapshot the running hash at the caller's chosen point. */
static void test_transcript_stage_ch_sh(void)
{
    quic_transcript t;
    u8 d[QUIC_SHA256_DIGEST];
    quic_transcript_init(&t);
    quic_transcript_add(&t, (const u8 *)"\x01\x00\x00\x03" "abc", 7);
    quic_transcript_ch_sh(&t, d); /* ClientHello..ServerHello stage */
    CHECK(ts_digest_eq(d,
        "6f50d04ebccfc92fab762e6ece797de3c0c6d62e02feb988d8dffe69a81566d4"));
}

static void test_transcript_stage_ch_sfin(void)
{
    quic_transcript t;
    u8 d[QUIC_SHA256_DIGEST];
    quic_transcript_init(&t);
    quic_transcript_add(&t, (const u8 *)"\x01\x00\x00\x03" "abc", 7);
    quic_transcript_add(&t, (const u8 *)"\x02\x00\x00\x03" "def", 7);
    quic_transcript_ch_sfin(&t, d); /* ClientHello..server Finished stage */
    CHECK(ts_digest_eq(d,
        "5bf53862cbd11fca4c1308918e02e4e39b0f13ad1c44b58411b5041df7294754"));
}

void test_transcript_stage(void)
{
    test_transcript_stage_ch_sh();
    test_transcript_stage_ch_sfin();
}
