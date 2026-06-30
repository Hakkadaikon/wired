#include "test.h"

void test_zerortt_policy(void)
{
    CHECK(quic_zerortt_safe(1, 0) == 1); /* idempotent */
    CHECK(quic_zerortt_safe(0, 1) == 1); /* replay protected */
    CHECK(quic_zerortt_safe(1, 1) == 1);
    CHECK(quic_zerortt_safe(0, 0) == 0); /* neither: unsafe */
}
