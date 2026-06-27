#include "test.h"

#define NAME(s) ((const u8 *)(s)), (sizeof(s) - 1)

/* Classification of pseudo, regular, and unknown names. */
static void test_ph_classify(void)
{
    CHECK(quic_h3_ph_classify(NAME(":method")) == QUIC_H3_PH_METHOD);
    CHECK(quic_h3_ph_classify(NAME(":status")) == QUIC_H3_PH_STATUS);
    CHECK(quic_h3_ph_classify(NAME("content-type")) == QUIC_H3_PH_NONE);
    CHECK(quic_h3_ph_classify(NAME(":bogus")) == QUIC_H3_PH_UNKNOWN);
    /* a prefix of a known name must not match */
    CHECK(quic_h3_ph_classify(NAME(":pat")) == QUIC_H3_PH_UNKNOWN);
    CHECK(quic_h3_ph_classify(NAME(":")) == QUIC_H3_PH_UNKNOWN);
}

/* A complete, well-ordered request is valid. */
static void test_ph_request_ok(void)
{
    quic_h3_ph_set p;
    quic_h3_ph_init(&p);
    quic_h3_ph_field(&p, NAME(":method"));
    quic_h3_ph_field(&p, NAME(":scheme"));
    quic_h3_ph_field(&p, NAME(":authority"));
    quic_h3_ph_field(&p, NAME(":path"));
    quic_h3_ph_field(&p, NAME("user-agent"));
    CHECK(quic_h3_ph_request_ok(&p) == 1);
    CHECK(quic_h3_ph_response_ok(&p) == 0); /* no :status */
}

/* Missing a required pseudo-header makes the request malformed. */
static void test_ph_request_missing(void)
{
    quic_h3_ph_set p;
    quic_h3_ph_init(&p);
    quic_h3_ph_field(&p, NAME(":method"));
    quic_h3_ph_field(&p, NAME(":scheme"));
    CHECK(quic_h3_ph_request_ok(&p) == 0); /* no :path */
}

/* A pseudo-header after a regular field is malformed. */
static void test_ph_order(void)
{
    quic_h3_ph_set p;
    quic_h3_ph_init(&p);
    quic_h3_ph_field(&p, NAME(":method"));
    quic_h3_ph_field(&p, NAME("accept"));
    quic_h3_ph_field(&p, NAME(":scheme")); /* pseudo after regular */
    quic_h3_ph_field(&p, NAME(":path"));
    CHECK(p.ok == 0);
    CHECK(quic_h3_ph_request_ok(&p) == 0);
}

/* A duplicate pseudo-header is malformed. */
static void test_ph_duplicate(void)
{
    quic_h3_ph_set p;
    quic_h3_ph_init(&p);
    quic_h3_ph_field(&p, NAME(":method"));
    quic_h3_ph_field(&p, NAME(":method"));
    CHECK(p.ok == 0);
}

/* An unknown pseudo-header is malformed. */
static void test_ph_unknown(void)
{
    quic_h3_ph_set p;
    quic_h3_ph_init(&p);
    quic_h3_ph_field(&p, NAME(":protocol"));
    CHECK(p.ok == 0);
}

/* A response needs only :status. */
static void test_ph_response_ok(void)
{
    quic_h3_ph_set p;
    quic_h3_ph_init(&p);
    quic_h3_ph_field(&p, NAME(":status"));
    quic_h3_ph_field(&p, NAME("content-length"));
    CHECK(quic_h3_ph_response_ok(&p) == 1);
    CHECK(quic_h3_ph_request_ok(&p) == 0);
}

void test_pseudoheader(void)
{
    test_ph_classify();
    test_ph_request_ok();
    test_ph_request_missing();
    test_ph_order();
    test_ph_duplicate();
    test_ph_unknown();
    test_ph_response_ok();
}
