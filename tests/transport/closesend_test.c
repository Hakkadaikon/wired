#include "test.h"

/* CONNECTION_CLOSE is warranted on an error or an expired idle timeout. */
static void test_closesend_should_close(void)
{
    CHECK(quic_idledrive_should_close(0, 0) == 0);
    CHECK(quic_idledrive_should_close(1, 0) == 1); /* error */
    CHECK(quic_idledrive_should_close(0, 1) == 1); /* idle expired */
    CHECK(quic_idledrive_should_close(1, 1) == 1);
}

void test_closesend(void)
{
    test_closesend_should_close();
}
