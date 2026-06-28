#include "test.h"

/* A loop set up so the only gate under test is the named one: keys installed,
 * path validated (anti-amp lifted), congestion window wide open. */
static void mk(quic_evloop *c)
{
    quic_evloop_init(c, QUIC_LEVEL_INITIAL, 1u << 20, 10);
    quic_initial_keys k = {0};
    quic_keyset_install(&c->gate.keys, QUIC_LEVEL_INITIAL, &k);
    c->gate.validated = 1;
}

/* RFC 9000 12: one iteration runs receive, then timers, then send -- never a
 * send before the receive that owed it is processed. */
static void test_iteration_order_receive_before_send(void)
{
    quic_evloop c;
    mk(&c);
    quic_evloop_on_receive(&c, 1); /* ack-eliciting: owes an ACK */
    CHECK(c.ack_owed == 0);        /* not processed until step */
    u64 pn_before = c.next_pn;
    quic_evloop_step(&c, 0);
    /* the receive was drained (ACK obligation arose) AND a send went out in the
     * same iteration, in that order */
    CHECK(c.next_pn == pn_before + 1);
    CHECK(c.ack_owed == 0); /* the send carried and cleared the ACK */
}

/* RFC 9000 13.2.1: an ack-eliciting receive owes an ACK that the next send
 * carries and clears; a non-eliciting receive owes nothing. */
static void test_ack_owed_then_cleared(void)
{
    quic_evloop c;
    mk(&c);
    quic_evloop_on_receive(&c, 0); /* non-eliciting */
    quic_evloop_step(&c, 0);
    CHECK(c.ack_owed == 0);
    CHECK(c.next_pn == 0); /* nothing owed, nothing to send */

    quic_evloop_on_receive(&c, 1); /* eliciting */
    quic_evloop_step(&c, 0);
    CHECK(c.next_pn == 1);  /* ACK sent */
    CHECK(c.ack_owed == 0); /* obligation cleared */
}

/* RFC 9002 6.2: a fired timer is disarmed before its action runs; one arming
 * yields at most one action. */
static void test_timer_disarm_before_act(void)
{
    quic_evloop c;
    mk(&c);
    c.cwnd = 0; /* hold the send phase so we observe the timer action alone */
    c.bytes_in_flight = 10;
    c.loss.armed = 1;
    c.loss.deadline = 0;
    quic_evloop_step(&c, 5);
    CHECK(c.loss.armed == 0);   /* disarmed by the fire */
    CHECK(c.rtx_n == 1);        /* its action ran exactly once */
    quic_evloop_step(&c, 5);
    CHECK(c.rtx_n == 1);        /* a stale arming cannot fire again */
}

/* RFC 9002 6.2: PTO never fires on an empty in-flight set. */
static void test_pto_not_on_empty_inflight(void)
{
    quic_evloop c;
    mk(&c);
    c.pto.armed = 1;
    c.pto.deadline = 0;
    u64 pn = c.next_pn;
    quic_evloop_step(&c, 9);
    CHECK(c.next_pn == pn); /* no probe: in-flight is empty */
}

/* RFC 9002 6.1: a loss timer firing queues a retransmission and pulls the
 * packet out of the in-flight byte count. */
static void test_loss_removes_inflight_queues_rtx(void)
{
    quic_evloop c;
    mk(&c);
    c.cwnd = 0; /* hold the send phase: observe the loss action's effect */
    c.bytes_in_flight = 10;
    c.loss.armed = 1;
    c.loss.deadline = 0;
    quic_evloop_step(&c, 1);
    CHECK(c.rtx_n == 1);            /* queued for retransmission */
    CHECK(c.bytes_in_flight == 0);  /* removed from in-flight */
}

/* RFC 9000 10.1: idle firing drives toward draining and stops normal sends. */
static void test_idle_moves_to_draining(void)
{
    quic_evloop c;
    mk(&c);
    c.have_new_data = 1;
    c.gate.handshake_complete = 1;
    c.idle.armed = 1;
    c.idle.deadline = 0;
    quic_evloop_step(&c, 1);
    CHECK(c.gate.phase != QUIC_CONNLOOP_ACTIVE);
    u64 pn = c.next_pn;
    quic_evloop_step(&c, 2);
    CHECK(c.next_pn == pn); /* no normal send once draining */
}

/* RFC 9002 6.2: firing one timer leaves the others' armed state untouched. */
static void test_timers_independent(void)
{
    quic_evloop c;
    mk(&c);
    c.bytes_in_flight = 10;
    c.loss.armed = 1; c.loss.deadline = 0;
    c.idle.armed = 1; c.idle.deadline = 100; /* not yet due */
    quic_evloop_step(&c, 1);
    CHECK(c.loss.armed == 0); /* fired */
    CHECK(c.idle.armed == 1); /* untouched */
}

/* RFC 9002 7.7 / RFC 9000 8.1: a send needs BOTH cwnd and anti-amp; either
 * gate alone blocks it. */
static void test_send_needs_both_gates(void)
{
    quic_evloop c;
    mk(&c);
    c.have_new_data = 1;
    c.gate.handshake_complete = 1;

    /* cwnd exhausted: no send even with budget */
    c.cwnd = 0;
    quic_evloop_step(&c, 0);
    CHECK(c.next_pn == 0);

    /* cwnd open but anti-amp exhausted: still no send */
    c.cwnd = 1u << 20;
    c.gate.validated = 0;
    c.gate.recv_bytes = 0;
    c.gate.sent_bytes = 100; /* over 3x of zero received */
    quic_evloop_step(&c, 0);
    CHECK(c.next_pn == 0);

    /* both open: send goes out */
    c.gate.validated = 1;
    quic_evloop_step(&c, 0);
    CHECK(c.next_pn == 1);
}

/* RFC 9000 8.1: the anti-amplification budget never admits a send that would
 * push sent past 3x received, and never goes negative. */
static void test_antiamp_nonnegative(void)
{
    quic_evloop c;
    mk(&c);
    c.have_new_data = 1;
    c.gate.handshake_complete = 1;
    c.gate.validated = 0;
    c.gate.recv_bytes = 3;   /* budget 9 bytes; send_len 10 exceeds it */
    c.gate.sent_bytes = 0;
    quic_evloop_step(&c, 0);
    CHECK(c.next_pn == 0); /* suppressed, no underflow */
}

/* RFC 9000 8.1: a PTO probe is also subject to the anti-amp budget. */
static void test_pto_probe_under_antiamp(void)
{
    quic_evloop c;
    mk(&c);
    c.bytes_in_flight = 10;
    c.gate.sent.e[0].used = 1;
    c.gate.sent.e[0].state = QUIC_SP_INFLIGHT;
    c.gate.validated = 0;
    c.gate.recv_bytes = 0;   /* no budget */
    c.gate.sent_bytes = 0;
    c.pto.armed = 1;
    c.pto.deadline = 0;
    u64 pn = c.next_pn;
    quic_evloop_step(&c, 1);
    CHECK(c.next_pn == pn); /* probe blocked by anti-amp */
}

/* RFC 9002 6 / A.1: a retransmission is sent under a fresh packet number and
 * tracked in flight; numbers are never reused. */
static void test_retransmit_new_pn_tracked(void)
{
    quic_evloop c;
    mk(&c);
    c.gate.handshake_complete = 1;
    /* a loss has queued one retransmission */
    c.rtx_n = 1;
    c.rtx[0].pn = 0;
    c.rtx[0].len = 10;
    u64 pn = c.next_pn;
    quic_evloop_step(&c, 0);
    CHECK(c.next_pn == pn + 1);       /* new number */
    CHECK(c.rtx_n == 0);              /* queue drained */
    CHECK(c.bytes_in_flight == 10);  /* tracked in flight */
}

/* RFC 9002 6: while a retransmission is pending, new data is not originated. */
static void test_retransmit_preempts_new_data(void)
{
    quic_evloop c;
    mk(&c);
    c.gate.handshake_complete = 1;
    c.have_new_data = 1;
    c.rtx_n = 2;
    c.rtx[0].pn = 0; c.rtx[0].len = 10;
    c.rtx[1].pn = 1; c.rtx[1].len = 10;
    quic_evloop_step(&c, 0);
    CHECK(c.rtx_n == 1); /* one retransmission consumed, not new data */
    quic_evloop_step(&c, 0);
    CHECK(c.rtx_n == 0); /* second retransmission before any new data */
}

/* RFC 9001 6.1: a key update only after the handshake is confirmed. */
static void test_key_update_after_confirmed_only(void)
{
    quic_evloop c;
    mk(&c);
    c.gate.handshake_confirmed = 0;
    CHECK(quic_evloop_initiate_key_update(&c, 100) == 0);
    CHECK(c.key_generation == 0);

    c.gate.handshake_confirmed = 1;
    CHECK(quic_evloop_initiate_key_update(&c, 100) == 1);
    CHECK(c.key_generation == 1);
}

/* RFC 9001 6.1: the prior generation's key is retained for 3*PTO, then
 * discarded; at most two generations are held at once. */
static void test_old_key_retain_then_discard(void)
{
    quic_evloop c;
    mk(&c);
    c.gate.handshake_confirmed = 1;
    c.pto_period = 10; /* retention window is 3*PTO = 30 */
    CHECK(quic_evloop_old_key_retained(&c, 0) == 0); /* gen 0: nothing prior */

    quic_evloop_initiate_key_update(&c, 100);
    CHECK(c.key_generation == 1);
    CHECK(quic_evloop_old_key_retained(&c, 120) == 1); /* within 30 */
    CHECK(quic_evloop_old_key_retained(&c, 140) == 0); /* past 3*PTO: discarded */
}

/* RFC 9000 10.2: once it leaves active, the connection never returns to it. */
static void test_close_never_returns_active(void)
{
    quic_evloop c;
    mk(&c);
    quic_evloop_close(&c, 0);
    CHECK(c.gate.phase != QUIC_CONNLOOP_ACTIVE);
    quic_evloop_close(&c, 1);
    CHECK(c.gate.phase != QUIC_CONNLOOP_ACTIVE);
}

/* RFC 9000 10.2: a closed connection does no further loop work. */
static void test_closed_does_nothing(void)
{
    quic_evloop c;
    mk(&c);
    c.gate.phase = QUIC_CONNLOOP_CLOSED;
    c.have_new_data = 1;
    c.gate.handshake_complete = 1;
    quic_evloop_on_receive(&c, 1);
    quic_evloop_step(&c, 0);
    CHECK(c.rx_n == 1);    /* receive not drained */
    CHECK(c.next_pn == 0); /* nothing sent */
    CHECK(c.ack_owed == 0);
}

/* Liveness: an owed ACK is eventually sent while the connection stays active
 * and the path validates. */
static void test_pending_ack_eventually_sent(void)
{
    quic_evloop c;
    mk(&c);
    c.gate.validated = 0;
    c.gate.sent_bytes = 100; /* anti-amp exhausted: send blocked at first */
    quic_evloop_on_receive(&c, 1);
    quic_evloop_step(&c, 0);
    CHECK(c.ack_owed == 1); /* still owed under the limit */
    c.gate.validated = 1;   /* path validates, lifting the limit */
    quic_evloop_run(&c, 0, 8);
    CHECK(c.ack_owed == 0); /* ACK eventually went out */
}

/* Liveness: pending retransmission is eventually drained while the loop runs
 * and the window allows. */
static void test_pending_rtx_eventually_drained(void)
{
    quic_evloop c;
    mk(&c);
    c.gate.handshake_complete = 1;
    c.cwnd = 1u << 20;
    c.rtx_n = 3;
    usz i;
    for (i = 0; i < 3; i++) { c.rtx[i].pn = i; c.rtx[i].len = 10; }
    quic_evloop_run(&c, 0, 16);
    CHECK(c.rtx_n == 0);
}

void test_evloop(void)
{
    test_iteration_order_receive_before_send();
    test_ack_owed_then_cleared();
    test_timer_disarm_before_act();
    test_pto_not_on_empty_inflight();
    test_loss_removes_inflight_queues_rtx();
    test_idle_moves_to_draining();
    test_timers_independent();
    test_send_needs_both_gates();
    test_antiamp_nonnegative();
    test_pto_probe_under_antiamp();
    test_retransmit_new_pn_tracked();
    test_retransmit_preempts_new_data();
    test_key_update_after_confirmed_only();
    test_old_key_retain_then_discard();
    test_close_never_returns_active();
    test_closed_does_nothing();
    test_pending_ack_eventually_sent();
    test_pending_rtx_eventually_drained();
}
