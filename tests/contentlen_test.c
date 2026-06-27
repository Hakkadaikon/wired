#include "test.h"

/* Received bytes must equal the declared Content-Length. */
static void test_contentlen_match(void)
{
    CHECK(quic_h3_content_length_ok(0, 0) == 1);
    CHECK(quic_h3_content_length_ok(10, 10) == 1);
    CHECK(quic_h3_content_length_ok(10, 9) == 0);  /* too few */
    CHECK(quic_h3_content_length_ok(10, 11) == 0); /* too many */
}

/* Bytes received so far exceeding the declared length is a violation. */
static void test_contentlen_exceeded(void)
{
    CHECK(quic_h3_content_length_exceeded(10, 5) == 0);
    CHECK(quic_h3_content_length_exceeded(10, 10) == 0); /* exact, not over */
    CHECK(quic_h3_content_length_exceeded(10, 11) == 1);
}

void test_contentlen(void)
{
    test_contentlen_match();
    test_contentlen_exceeded();
}
