#include "test.h"

/* RFC 9001 4.9: the send level never regresses across the connection's life. */
static void test_send_level_never_regresses(void)
{
    quic_connloop c;
    quic_connloop_init(&c, 1);
    c.validated = 1; /* lift anti-amp so the gate under test is the level */
    quic_initial_keys k = {0};
    quic_keyset_install(&c.keys, QUIC_LEVEL_INITIAL, &k);
    quic_keyset_install(&c.keys, QUIC_LEVEL_HANDSHAKE, &k);

    CHECK(quic_connloop_on_send(&c, QUIC_LEVEL_INITIAL, 1, 0, 10) == 1);
    int before = c.send_level;
    CHECK(before == QUIC_LEVEL_INITIAL);
    /* promote up to Handshake: allowed */
    CHECK(quic_connloop_on_send(&c, QUIC_LEVEL_HANDSHAKE, 1, 1, 10) == 1);
    CHECK(c.send_level == QUIC_LEVEL_HANDSHAKE);
    /* regress back to Initial: refused, level unchanged (before/after) */
    int hi = c.send_level;
    CHECK(quic_connloop_on_send(&c, QUIC_LEVEL_INITIAL, 1, 2, 10) == 0);
    CHECK(c.send_level == hi);
}

/* RFC 9001 4.9: no 1-RTT (application) data before the handshake is complete. */
static void test_no_app_data_before_handshake_complete(void)
{
    quic_connloop c;
    quic_connloop_init(&c, 1);
    c.validated = 1;
    quic_initial_keys k = {0};
    quic_keyset_install(&c.keys, QUIC_LEVEL_INITIAL, &k);
    quic_keyset_install(&c.keys, QUIC_LEVEL_HANDSHAKE, &k);
    quic_keyset_install(&c.keys, QUIC_LEVEL_ONERTT, &k);
    quic_connloop_on_send(&c, QUIC_LEVEL_INITIAL, 1, 0, 10);
    quic_connloop_on_send(&c, QUIC_LEVEL_HANDSHAKE, 1, 1, 10);

    /* handshake not complete: 1-RTT send refused */
    CHECK(quic_connloop_on_send(&c, QUIC_LEVEL_ONERTT, 1, 2, 10) == 0);
    CHECK(c.send_level == QUIC_LEVEL_HANDSHAKE);

    /* after completion: 1-RTT send allowed */
    c.handshake_complete = 1;
    CHECK(quic_connloop_on_send(&c, QUIC_LEVEL_ONERTT, 1, 2, 10) == 1);
    CHECK(c.send_level == QUIC_LEVEL_ONERTT);
}

/* RFC 9000 8.1: a server sends at most 3x the bytes it has received before
 * the address is validated. */
static void test_server_send_capped_3x_recv(void)
{
    quic_connloop c;
    quic_connloop_init(&c, 1);
    quic_initial_keys k = {0};
    quic_keyset_install(&c.keys, QUIC_LEVEL_INITIAL, &k);

    quic_connloop_on_recv(&c, QUIC_LEVEL_INITIAL, 100); /* budget = 300 */
    CHECK(c.recv_bytes == 100);
    /* exactly 3x allowed */
    CHECK(quic_connloop_on_send(&c, QUIC_LEVEL_INITIAL, 1, 0, 300) == 1);
    CHECK(c.sent_bytes == 300);
    /* one more byte exceeds 3x: refused, sent_bytes unchanged (before/after) */
    u64 before = c.sent_bytes;
    CHECK(quic_connloop_on_send(&c, QUIC_LEVEL_INITIAL, 1, 1, 1) == 0);
    CHECK(c.sent_bytes == before);
}

/* RFC 9001 4: a recv at an un-installed level does not advance state. */
static void test_recv_drops_packet_without_key(void)
{
    quic_connloop c;
    quic_connloop_init(&c, 1);
    /* Handshake key not installed */
    CHECK(quic_connloop_on_recv(&c, QUIC_LEVEL_HANDSHAKE, 50) == 0);
    /* received-byte accounting still moves (RFC 9000 8.1) */
    CHECK(c.recv_bytes == 50);
}

/* RFC 9000 10.2: a closed connection processes no incoming packet. */
static void test_closed_processes_no_packet(void)
{
    quic_connloop c;
    quic_connloop_init(&c, 1);
    quic_initial_keys k = {0};
    quic_keyset_install(&c.keys, QUIC_LEVEL_INITIAL, &k);
    c.phase = QUIC_CONNLOOP_CLOSED;
    u64 before = c.recv_bytes;
    CHECK(quic_connloop_on_recv(&c, QUIC_LEVEL_INITIAL, 50) == 0);
    CHECK(c.recv_bytes == before); /* no advance at all while closed */
}

/* RFC 9002 5.1: an ACK removes the acknowledged tracked packets; an ACK for
 * an untracked packet removes nothing. */
static void test_ack_removes_tracked_packet(void)
{
    quic_connloop c;
    quic_connloop_init(&c, 1);
    c.validated = 1;
    quic_initial_keys k = {0};
    quic_keyset_install(&c.keys, QUIC_LEVEL_INITIAL, &k);
    quic_connloop_on_send(&c, QUIC_LEVEL_INITIAL, 1, 0, 10);
    quic_connloop_on_send(&c, QUIC_LEVEL_INITIAL, 1, 1, 10);
    CHECK(quic_sentpkt_count(&c.sent) == 2);

    /* spurious ACK for pn 9 (never sent): removes nothing */
    u64 spur = 0;
    CHECK(quic_connloop_on_ack(&c, 9, &spur, 1) == 0);
    CHECK(quic_sentpkt_count(&c.sent) == 2);

    /* ACK pn 0..1 (largest 1, first range covers down to 0): removes both */
    u64 r = 1;
    usz before = quic_sentpkt_count(&c.sent);
    CHECK(quic_connloop_on_ack(&c, 1, &r, 1) == 2);
    CHECK(quic_sentpkt_count(&c.sent) < before);
    CHECK(quic_sentpkt_count(&c.sent) == 0);
    CHECK(c.pto_armed == 0); /* emptying in-flight disarms PTO */
}

/* RFC 9002 6.2: a PTO probe is added without abandoning in-flight packets;
 * PTO never arms on an empty in-flight set. */
static void test_pto_sends_probe_keeps_inflight(void)
{
    quic_connloop c;
    quic_connloop_init(&c, 1);
    c.validated = 1;
    quic_initial_keys k = {0};
    quic_keyset_install(&c.keys, QUIC_LEVEL_INITIAL, &k);

    /* empty in-flight: PTO refuses, stays disarmed */
    CHECK(quic_connloop_on_pto(&c, QUIC_LEVEL_INITIAL, 0, 10) == 0);
    CHECK(c.pto_armed == 0);

    quic_connloop_on_send(&c, QUIC_LEVEL_INITIAL, 1, 0, 10);
    CHECK(c.pto_armed == 1);
    usz before = quic_sentpkt_count(&c.sent);
    /* probe adds a packet, never shrinks in-flight (before/after) */
    CHECK(quic_connloop_on_pto(&c, QUIC_LEVEL_INITIAL, 1, 10) == 1);
    CHECK(quic_sentpkt_count(&c.sent) >= before);
    CHECK(quic_sentpkt_count(&c.sent) == before + 1);
}

/* RFC 9000 10.2: closing/draining/closed never return to an open phase. */
static void test_closing_never_returns_open(void)
{
    quic_connloop c;
    quic_connloop_init(&c, 1);
    CHECK(c.phase == QUIC_CONNLOOP_ACTIVE);

    quic_connloop_close(&c, 0); /* local close */
    int after_local = c.phase;
    CHECK(after_local == QUIC_CONNLOOP_CLOSING);

    quic_connloop_close(&c, 0); /* advance closing -> draining */
    CHECK(c.phase == QUIC_CONNLOOP_DRAINING);
    quic_connloop_close(&c, 0); /* draining -> closed */
    CHECK(c.phase == QUIC_CONNLOOP_CLOSED);

    /* never returns to active no matter the event (before/after) */
    int closed = c.phase;
    quic_connloop_close(&c, 1);
    CHECK(c.phase == closed);
    CHECK(c.phase != QUIC_CONNLOOP_ACTIVE);
}

/* RFC 9000 10.2: no new application data while closing/draining/closed. */
static void test_closing_sends_no_app_data(void)
{
    quic_connloop c;
    quic_connloop_init(&c, 1);
    c.validated = 1;
    c.handshake_complete = 1;
    quic_initial_keys k = {0};
    quic_keyset_install(&c.keys, QUIC_LEVEL_ONERTT, &k);
    c.send_level = QUIC_LEVEL_HANDSHAKE;
    quic_connloop_close(&c, 0); /* -> closing */
    CHECK(quic_connloop_on_send(&c, QUIC_LEVEL_ONERTT, 1, 0, 10) == 0);
}

/* RFC 9001 4.9.1: a discarded level is never used to process again. */
static void test_no_recv_at_discarded_level(void)
{
    quic_connloop c;
    quic_connloop_init(&c, 1);
    quic_initial_keys k = {0};
    quic_keyset_install(&c.keys, QUIC_LEVEL_INITIAL, &k);
    CHECK(quic_connloop_on_recv(&c, QUIC_LEVEL_INITIAL, 10) == 1);
    quic_keyset_discard(&c.keys, QUIC_LEVEL_INITIAL);
    /* after discard: processing at that level refused */
    CHECK(quic_connloop_on_recv(&c, QUIC_LEVEL_INITIAL, 10) == 0);
}

/* End-to-end convergence: a client and server drive Initial -> Handshake ->
 * 1-RTT key promotion, complete the handshake, and exchange app data, with
 * in-flight draining via ACK (RFC 9001 4.1, RFC 9002 5.1). */
static void test_handshake_progress_reaches_confirmed(void)
{
    quic_connloop cl, sv;
    quic_connloop_init(&cl, 0);
    quic_connloop_init(&sv, 1);
    cl.validated = 1;
    sv.validated = 1;
    quic_initial_keys k = {0};
    int lv;
    for (lv = QUIC_LEVEL_INITIAL; lv <= QUIC_LEVEL_ONERTT; lv++) {
        quic_keyset_install(&cl.keys, lv, &k);
        quic_keyset_install(&sv.keys, lv, &k);
    }
    /* Initial then Handshake exchange */
    CHECK(quic_connloop_on_send(&cl, QUIC_LEVEL_INITIAL, 1, 0, 20) == 1);
    CHECK(quic_connloop_on_recv(&sv, QUIC_LEVEL_INITIAL, 20) == 1);
    CHECK(quic_connloop_on_send(&sv, QUIC_LEVEL_INITIAL, 1, 0, 20) == 1);
    CHECK(quic_connloop_on_send(&cl, QUIC_LEVEL_HANDSHAKE, 1, 1, 20) == 1);
    CHECK(quic_connloop_on_recv(&sv, QUIC_LEVEL_HANDSHAKE, 20) == 1);

    /* handshake completes on both ends, then app data over 1-RTT */
    cl.handshake_complete = 1;
    sv.handshake_complete = 1;
    CHECK(quic_connloop_on_send(&cl, QUIC_LEVEL_ONERTT, 1, 2, 20) == 1);
    CHECK(cl.send_level == QUIC_LEVEL_ONERTT);
    CHECK(quic_connloop_on_recv(&sv, QUIC_LEVEL_ONERTT, 20) == 1);

    /* client's in-flight drains to empty via ACKs (pn 0..2) */
    CHECK(quic_sentpkt_count(&cl.sent) == 3);
    u64 r = 2;
    quic_connloop_on_ack(&cl, 2, &r, 1);
    CHECK(quic_sentpkt_count(&cl.sent) == 0);
    CHECK(cl.pto_armed == 0);
}

void test_connloop(void)
{
    test_send_level_never_regresses();
    test_no_app_data_before_handshake_complete();
    test_server_send_capped_3x_recv();
    test_recv_drops_packet_without_key();
    test_closed_processes_no_packet();
    test_ack_removes_tracked_packet();
    test_pto_sends_probe_keeps_inflight();
    test_closing_never_returns_open();
    test_closing_sends_no_app_data();
    test_no_recv_at_discarded_level();
    test_handshake_progress_reaches_confirmed();
}
