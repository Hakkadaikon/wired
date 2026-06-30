#include "test.h"

/* RFC 9001 6.2/6.3: matching phase uses current keys, mismatch tries next. */
void test_kudrive_recv_phase(void)
{
    /* match -> generation 0 (current) */
    CHECK(quic_kudrive_key_generation(0, 0, 0) == 0);
    CHECK(quic_kudrive_key_generation(1, 1, 0) == 0);

    /* mismatch -> generation 1 (next), regardless of in-progress flag */
    CHECK(quic_kudrive_key_generation(1, 0, 0) == 1);
    CHECK(quic_kudrive_key_generation(0, 1, 0) == 1);
    CHECK(quic_kudrive_key_generation(1, 0, 1) == 1);
}
