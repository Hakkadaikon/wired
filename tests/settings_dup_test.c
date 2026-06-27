#include "test.h"

/* Distinct identifiers are all accepted. */
static void test_settings_dup_distinct(void)
{
    quic_h3_settings_seen s;
    quic_h3_settings_seen_init(&s);
    CHECK(quic_h3_settings_mark(&s, 0x01) == 1);
    CHECK(quic_h3_settings_mark(&s, 0x06) == 1);
    CHECK(quic_h3_settings_mark(&s, 0x07) == 1);
}

/* A repeated identifier is rejected (H3_SETTINGS_ERROR). */
static void test_settings_dup_repeat(void)
{
    quic_h3_settings_seen s;
    quic_h3_settings_seen_init(&s);
    CHECK(quic_h3_settings_mark(&s, 0x06) == 1);
    CHECK(quic_h3_settings_mark(&s, 0x06) == 0);
}

/* Marking past the capacity is rejected. */
static void test_settings_dup_full(void)
{
    quic_h3_settings_seen s;
    quic_h3_settings_seen_init(&s);
    for (u64 i = 0; i < QUIC_H3_SETTINGS_SEEN_MAX; i++)
        CHECK(quic_h3_settings_mark(&s, 0x100 + i) == 1);
    CHECK(quic_h3_settings_mark(&s, 0x999) == 0);
}

void test_settings_dup(void)
{
    test_settings_dup_distinct();
    test_settings_dup_repeat();
    test_settings_dup_full();
}
