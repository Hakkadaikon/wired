#include "test.h"

/* RFC 9369 3.3.1 v2 Initial salt, exact golden value. */
static const u8 V2_GOLDEN[20] = {
    0x0d,0xed,0xe3,0xde,0xf7,0x00,0xa6,0xdb,0x81,0x93,
    0x81,0xbe,0x6e,0x26,0x9d,0xcb,0xf9,0xbd,0x2e,0xd9
};

/* RFC 9001 5.2 v1 Initial salt, exact golden value. */
static const u8 V1_GOLDEN[20] = {
    0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,
    0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a
};

static int same(const u8 *a, const u8 *b, usz n)
{
    for (usz i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}

static void test_salt_values(void)
{
    const u8 *s; usz len;
    CHECK(quic_version_initial_salt(QUIC_VERSION_1, &s, &len) == 1);
    CHECK(len == 20 && same(s, V1_GOLDEN, 20));
    CHECK(quic_version_initial_salt(QUIC_VERSION_2, &s, &len) == 1);
    CHECK(len == 20 && same(s, V2_GOLDEN, 20));
}

/* The two salts must actually differ (catches a copy-paste of one constant). */
static void test_salts_differ(void)
{
    CHECK(!same(V1_GOLDEN, V2_GOLDEN, 20));
}

static void test_unknown_version(void)
{
    const u8 *s = (const u8 *)0x1; usz len = 99;
    CHECK(quic_version_initial_salt(0xdeadbeefu, &s, &len) == 0);
    CHECK(s == (const u8 *)0x1 && len == 99); /* outputs untouched */
}

/* RFC 9369 3.3.1 label prefixes: "quic " (v1) vs "quicv2 " (v2). */
static void test_label_prefix(void)
{
    const char *p; usz len;
    CHECK(quic_version_label_prefix(QUIC_VERSION_1, &p, &len) == 1);
    CHECK(len == 5 && p[0] == 'q' && p[4] == ' ');
    CHECK(quic_version_label_prefix(QUIC_VERSION_2, &p, &len) == 1);
    CHECK(len == 7 && p[4] == 'v' && p[5] == '2' && p[6] == ' ');
    CHECK(quic_version_label_prefix(0u, &p, &len) == 0);
}

void test_v2keys(void)
{
    test_salt_values();
    test_salts_differ();
    test_unknown_version();
    test_label_prefix();
}
