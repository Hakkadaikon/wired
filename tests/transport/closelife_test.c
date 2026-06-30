#include "test.h"

/* Idle timeout fires at the limit and closes silently (no CONNECTION_CLOSE). */
static void test_life_idle_silent_close(void)
{
    quic_life l;
    quic_life_init(&l, 3, 5);
    quic_life_tick(&l); quic_life_tick(&l);
    CHECK(l.phase == QUIC_LIFE_OPEN);
    quic_life_tick(&l); /* third tick reaches idle_max */
    CHECK(l.phase == QUIC_LIFE_CLOSED && l.sent_close == 0);
}

/* Receiving a packet resets the idle timer. */
static void test_life_recv_resets_idle(void)
{
    quic_life l;
    quic_life_init(&l, 3, 5);
    quic_life_tick(&l); quic_life_tick(&l);
    quic_life_on_recv(&l);
    CHECK(l.idle_ticks == 0);
    quic_life_tick(&l); quic_life_tick(&l);
    CHECK(l.phase == QUIC_LIFE_OPEN); /* did not close: timer was reset */
}

/* Immediate close enters CLOSING (sent_close set) and drains to CLOSED. */
static void test_life_immediate_close(void)
{
    quic_life l;
    quic_life_init(&l, 10, 2);
    quic_life_close(&l);
    CHECK(l.phase == QUIC_LIFE_CLOSING && l.sent_close == 1);
    quic_life_tick(&l); quic_life_tick(&l);
    CHECK(l.phase == QUIC_LIFE_CLOSED);
}

/* Peer CONNECTION_CLOSE enters DRAINING (no sent_close) and drains to CLOSED. */
static void test_life_draining(void)
{
    quic_life l;
    quic_life_init(&l, 10, 2);
    quic_life_on_peer_close(&l);
    CHECK(l.phase == QUIC_LIFE_DRAINING && l.sent_close == 0);
    quic_life_tick(&l); quic_life_tick(&l);
    CHECK(l.phase == QUIC_LIFE_CLOSED);
}

/* Stateless reset closes immediately. */
static void test_life_reset(void)
{
    quic_life l;
    quic_life_init(&l, 10, 10);
    quic_life_on_reset(&l);
    CHECK(l.phase == QUIC_LIFE_CLOSED);
}

/* CLOSED is terminal and the lifecycle is one-way: no event reopens it. */
static void test_life_closed_terminal(void)
{
    quic_life l;
    quic_life_init(&l, 10, 10);
    quic_life_on_reset(&l); /* -> CLOSED */
    quic_life_tick(&l);
    quic_life_on_recv(&l);
    quic_life_close(&l);
    quic_life_on_peer_close(&l);
    quic_life_on_reset(&l);
    CHECK(l.phase == QUIC_LIFE_CLOSED); /* stays closed through everything */

    /* once CLOSING, a peer close does not move back to open/draining */
    quic_life l2;
    quic_life_init(&l2, 10, 10);
    quic_life_close(&l2);
    quic_life_on_peer_close(&l2);
    CHECK(l2.phase == QUIC_LIFE_CLOSING); /* did not reopen or switch */
}

/* A sent ack-eliciting packet resets the idle timer (RFC 9000 10.1). */
static void test_life_send_resets_idle(void)
{
    quic_life l;
    quic_life_init(&l, 3, 5);
    quic_life_tick(&l); quic_life_tick(&l);
    quic_life_on_send(&l);
    CHECK(l.idle_ticks == 0);
    quic_life_tick(&l); quic_life_tick(&l);
    CHECK(l.phase == QUIC_LIFE_OPEN); /* did not close: timer was reset */
}

/* Entering the close path notifies the app exactly once (RFC 9000 10.2). */
static void test_life_notify_once_on_close(void)
{
    quic_life l;
    quic_life_init(&l, 10, 2);
    CHECK(l.notified == 0);
    quic_life_close(&l);
    CHECK(l.notified == 1);
    /* a later peer close is ignored (one-way), so no second notification */
    quic_life_on_peer_close(&l);
    CHECK(l.notified == 1 && l.phase == QUIC_LIFE_CLOSING);

    /* peer close path also notifies once */
    quic_life d;
    quic_life_init(&d, 10, 2);
    quic_life_on_peer_close(&d);
    CHECK(d.notified == 1 && d.phase == QUIC_LIFE_DRAINING);
}

/* An idle silent close does NOT notify the app (RFC 9000 10.1). */
static void test_life_idle_close_does_not_notify(void)
{
    quic_life l;
    quic_life_init(&l, 2, 5);
    quic_life_tick(&l); quic_life_tick(&l); /* idle silent close */
    CHECK(l.phase == QUIC_LIFE_CLOSED && l.notified == 0);
}

void test_closelife(void)
{
    test_life_idle_silent_close();
    test_life_recv_resets_idle();
    test_life_send_resets_idle();
    test_life_immediate_close();
    test_life_draining();
    test_life_reset();
    test_life_closed_terminal();
    test_life_notify_once_on_close();
    test_life_idle_close_does_not_notify();
}
