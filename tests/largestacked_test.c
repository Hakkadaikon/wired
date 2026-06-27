#include "test.h"

/* RFC 9002 A.7: largest_acked is monotonic and never regresses. */
static void test_largestacked_update(void)
{
    CHECK(quic_largest_acked_update(5, 9) == 9);
    CHECK(quic_largest_acked_update(9, 5) == 9); /* no regress */
    CHECK(quic_largest_acked_update(7, 7) == 7);
    CHECK(quic_largest_acked_update(0, 0) == 0);
}

/* RFC 9002 A.7: a packet is newly acked only when above the prior largest. */
static void test_largestacked_newly(void)
{
    CHECK(quic_newly_acked(5, 6) == 1);
    CHECK(quic_newly_acked(5, 5) == 0); /* boundary: equal is not new */
    CHECK(quic_newly_acked(5, 4) == 0);
}

void test_largestacked(void)
{
    test_largestacked_update();
    test_largestacked_newly();
}
