#include "test.h"
#include "transport/version/version/version.h"

/* RFC 9368 3: encode then decode reproduces Chosen + Available. */
static void test_verinfo_roundtrip(void)
{
    quic_version_information in = {QUIC_VERSION_1, 2,
                                  {QUIC_VERSION_1, QUIC_VERSION_2}};
    u8 buf[64];
    usz n = quic_verinfo_encode(buf, sizeof buf, &in);
    CHECK(n == 4 + 4 * 2);

    quic_version_information out;
    CHECK(quic_verinfo_decode(buf, n, &out) == n);
    CHECK(out.chosen == QUIC_VERSION_1);
    CHECK(out.count == 2);
    CHECK(out.available[0] == QUIC_VERSION_1);
    CHECK(out.available[1] == QUIC_VERSION_2);
}

/* Wire bytes are 4 big-endian bytes per version. */
static void test_verinfo_wire_be(void)
{
    quic_version_information in = {QUIC_VERSION_1, 1, {QUIC_VERSION_2}};
    u8 buf[8];
    CHECK(quic_verinfo_encode(buf, sizeof buf, &in) == 8);
    CHECK(buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 1);
    CHECK(buf[4] == 0x6b && buf[5] == 0x33 && buf[6] == 0x43 && buf[7] == 0xcf);
}

/* Chosen Version with an empty Available Versions list is well-formed. */
static void test_verinfo_chosen_only(void)
{
    quic_version_information in = {QUIC_VERSION_2, 0, {0}};
    u8 buf[8];
    usz n = quic_verinfo_encode(buf, sizeof buf, &in);
    CHECK(n == 4);
    quic_version_information out;
    CHECK(quic_verinfo_decode(buf, n, &out) == 4);
    CHECK(out.chosen == QUIC_VERSION_2 && out.count == 0);
}

/* Encode fails when the buffer cannot hold the value. */
static void test_verinfo_encode_no_room(void)
{
    quic_version_information in = {QUIC_VERSION_1, 1, {QUIC_VERSION_2}};
    u8 buf[7];
    CHECK(quic_verinfo_encode(buf, sizeof buf, &in) == 0);
}

/* Decode rejects truncated and misaligned lengths. */
static void test_verinfo_decode_bad(void)
{
    u8 buf[8] = {0};
    CHECK(quic_verinfo_decode(buf, 0, (quic_version_information[]){{0}}) == 0);
    CHECK(quic_verinfo_decode(buf, 3, (quic_version_information[]){{0}}) == 0);
    CHECK(quic_verinfo_decode(buf, 6, (quic_version_information[]){{0}}) == 0);
}

void test_verinfo(void)
{
    test_verinfo_roundtrip();
    test_verinfo_wire_be();
    test_verinfo_chosen_only();
    test_verinfo_encode_no_room();
    test_verinfo_decode_bad();
}
