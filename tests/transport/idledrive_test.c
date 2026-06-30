#include "test.h"

/* Activity then enough elapsed time fires the idle timeout. */
static void test_idledrive_expires_after_activity(void)
{
    quic_idledrive s;
    quic_idledrive_init(&s, 30);
    quic_idledrive_on_activity(&s, 100);
    CHECK(quic_idledrive_expired(&s, 129) == 0); /* before the limit */
    CHECK(quic_idledrive_expired(&s, 130) == 1); /* exactly the limit: fires */
}

/* Fresh activity keeps the connection alive. */
static void test_idledrive_activity_resets(void)
{
    quic_idledrive s;
    quic_idledrive_init(&s, 30);
    quic_idledrive_on_activity(&s, 100);
    quic_idledrive_on_activity(&s, 200);
    CHECK(quic_idledrive_expired(&s, 220) == 0);
}

/* A zero timeout never expires. */
static void test_idledrive_zero_never_expires(void)
{
    quic_idledrive s;
    quic_idledrive_init(&s, 0);
    quic_idledrive_on_activity(&s, 100);
    CHECK(quic_idledrive_expired(&s, 1000000) == 0);
}

void test_idledrive(void)
{
    test_idledrive_expires_after_activity();
    test_idledrive_activity_resets();
    test_idledrive_zero_never_expires();
}
