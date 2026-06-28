#include "test.h"
#include "qpack/dyntable.h"

/* RFC 9204 3.2.1: entry_size = name_len + value_len + 32. */
static void test_insert_size(void)
{
    quic_qpack_dyn t;
    quic_qpack_dyn_init(&t, 4096);
    CHECK(quic_qpack_dyn_insert(&t, (const u8 *)"abc", 3, (const u8 *)"xy", 2) == 1);
    CHECK(quic_qpack_dyn_size(&t) == 3 + 2 + 32);
    CHECK(quic_qpack_dyn_insert(&t, (const u8 *)"k", 1, (const u8 *)"v", 1) == 1);
    CHECK(quic_qpack_dyn_size(&t) == (3 + 2 + 32) + (1 + 1 + 32));
}

/* RFC 9204 3.2.2: exceeding capacity evicts the oldest entry. */
static void test_evict_on_overflow(void)
{
    quic_qpack_dyn t;
    /* each entry: 1 + 1 + 32 = 34; capacity holds two but not three. */
    quic_qpack_dyn_init(&t, 70);
    CHECK(quic_qpack_dyn_insert(&t, (const u8 *)"a", 1, (const u8 *)"1", 1) == 1);
    CHECK(quic_qpack_dyn_insert(&t, (const u8 *)"b", 1, (const u8 *)"2", 1) == 1);
    CHECK(quic_qpack_dyn_insert(&t, (const u8 *)"c", 1, (const u8 *)"3", 1) == 1);
    CHECK(quic_qpack_dyn_size(&t) == 68);
    /* "a" (abs 0) evicted, "b","c" (abs 1,2) live. */
    CHECK(t.dropped == 1);
}

/* RFC 9204 3.2.2: an entry larger than capacity is rejected, table unchanged. */
static void test_too_big_rejected(void)
{
    quic_qpack_dyn t;
    quic_qpack_dyn_init(&t, 40);
    CHECK(quic_qpack_dyn_insert(&t, (const u8 *)"name", 4, (const u8 *)"value", 5) == 0);
    CHECK(quic_qpack_dyn_size(&t) == 0);
    CHECK(t.count == 0);
}

void test_dyntable(void)
{
    test_insert_size();
    test_evict_on_overflow();
    test_too_big_rejected();
}
