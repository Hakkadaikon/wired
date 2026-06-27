#include "test.h"
#include "h3/connect.c"

/* method=CONNECT with :authority and no :scheme/:path is valid. */
static void test_connect_ok(void)
{
    CHECK(quic_h3_connect_ok(1, 1, 0, 0) == 1);
}

/* Missing :method CONNECT or :authority is invalid. */
static void test_connect_required(void)
{
    CHECK(quic_h3_connect_ok(0, 1, 0, 0) == 0); /* not CONNECT */
    CHECK(quic_h3_connect_ok(1, 0, 0, 0) == 0); /* no :authority */
}

/* Presence of :scheme or :path is forbidden. */
static void test_connect_forbidden(void)
{
    CHECK(quic_h3_connect_ok(1, 1, 1, 0) == 0); /* has :scheme */
    CHECK(quic_h3_connect_ok(1, 1, 0, 1) == 0); /* has :path */
    CHECK(quic_h3_connect_ok(1, 1, 1, 1) == 0); /* both */
}

void test_connect(void)
{
    test_connect_ok();
    test_connect_required();
    test_connect_forbidden();
}
