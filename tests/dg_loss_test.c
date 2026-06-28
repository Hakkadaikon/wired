#include "test.h"

/* A lost DATAGRAM frame is reported to the application. */
void test_dg_loss_notifies(void)
{
    CHECK(quic_dgdeliver_on_loss(1) == 1);
}

/* Loss of a non-DATAGRAM frame is not this layer's concern. */
void test_dg_loss_ignores_other(void)
{
    CHECK(quic_dgdeliver_on_loss(0) == 0);
}

/* DATAGRAM frames are never retransmitted. */
void test_dg_loss_never_retransmit(void)
{
    CHECK(quic_dgdeliver_retransmit_never() == 0);
}
