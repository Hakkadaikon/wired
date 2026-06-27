#include "test.h"
#include "manage/middlebox.c"

static void test_initial_ok(void)
{
    CHECK(!quic_middlebox_initial_ok(1199)); /* below minimum */
    CHECK(quic_middlebox_initial_ok(1200));  /* at minimum: ok */
    CHECK(quic_middlebox_initial_ok(1500));  /* above minimum */
}

static void test_port_expected(void)
{
    CHECK(quic_middlebox_port_expected(443));
    CHECK(!quic_middlebox_port_expected(80));
    CHECK(!quic_middlebox_port_expected(0));
}

void test_middlebox(void)
{
    test_initial_ok();
    test_port_expected();
}
