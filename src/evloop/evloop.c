#include "evloop/evloop.h"
#include "ackgen/ackgen.h"
#include "cwndctl/cwndctl.h"
#include "udploop/antiamp_gate.h"
#include "keyupdate/initiate.h"
#include "keyupdate/oldkey.h"

void quic_evloop_init(quic_evloop *c, int level, u64 cwnd, usz send_len)
{
    quic_connloop_init(&c->gate, 1);
    c->level = level;
    c->next_pn = 0;
    c->rx_n = 0;
    c->ack_owed = 0;
    c->rtx_n = 0;
    c->have_new_data = 0;
    c->send_len = send_len;
    c->pto.armed = c->loss.armed = c->idle.armed = 0;
    c->pto.deadline = c->loss.deadline = c->idle.deadline = 0;
    c->cwnd = cwnd;
    c->bytes_in_flight = 0;
    c->key_generation = 0;
    c->key_update_time = 0;
    c->pto_period = 0;
}

void quic_evloop_on_receive(quic_evloop *c, int ack_eliciting)
{
    if (c->rx_n >= QUIC_EVLOOP_QCAP) return;
    c->rx[c->rx_n++].ack_eliciting = ack_eliciting;
}

/* RFC 9000 13.2.1: an ack-eliciting receive owes an ACK; others do not. */
static void drain_one(quic_evloop *c, const quic_evloop_rx *r)
{
    quic_connloop_on_recv(&c->gate, c->level, c->send_len);
    if (r->ack_eliciting) c->ack_owed = 1;
}

/* Phase 1: process every queued receive, then clear the queue. */
static void phase_receive(quic_evloop *c)
{
    usz i;
    for (i = 0; i < c->rx_n; i++) drain_one(c, &c->rx[i]);
    c->rx_n = 0;
}

/* RFC 9002 6.2: a timer fires only when armed and its deadline has passed. */
static int timer_fires(const quic_evloop_timer *t, u64 now)
{
    return t->armed && now >= t->deadline;
}

/* RFC 9002 6.1: the loss timer pulls the oldest in-flight packet out and
 * queues its data for retransmission under a fresh number. */
static void loss_act(quic_evloop *c)
{
    if (c->rtx_n >= QUIC_EVLOOP_QCAP) return;
    c->rtx[c->rtx_n].pn = c->next_pn; /* placeholder: the lost original */
    c->rtx[c->rtx_n].len = c->send_len;
    c->rtx_n++;
    if (c->bytes_in_flight >= c->send_len) c->bytes_in_flight -= c->send_len;
}

/* RFC 9000 8.1: even a PTO probe is subject to the anti-amplification budget on
 * an unvalidated path. */
static int antiamp_ok(const quic_evloop *c)
{
    return quic_udploop_send_allowed(c->gate.recv_bytes, c->gate.sent_bytes,
                                     c->gate.validated, c->send_len);
}

/* RFC 9002 6.2: PTO acts only with ack-eliciting data in flight (delegated to
 * the gate, which refuses on an empty in-flight set) and within the amp budget. */
static void pto_act(quic_evloop *c)
{
    if (!antiamp_ok(c)) return;
    if (quic_connloop_on_pto(&c->gate, c->level, c->next_pn, c->send_len))
        c->next_pn++;
}

/* RFC 9000 10.1: idle expiry moves the connection toward draining. */
static void idle_act(quic_evloop *c)
{
    quic_connloop_close(&c->gate, 0);
}

/* Disarm-then-act one timer: clear armed first so a stale arming cannot fire
 * the action twice. */
static void run_timer(quic_evloop_timer *t, u64 now, void (*act)(quic_evloop *),
                      quic_evloop *c)
{
    if (!timer_fires(t, now)) return;
    t->armed = 0;
    act(c);
}

/* Phase 2: disarm-then-act each timer independently. */
static void phase_timers(quic_evloop *c, u64 now)
{
    run_timer(&c->pto, now, pto_act, c);
    run_timer(&c->loss, now, loss_act, c);
    run_timer(&c->idle, now, idle_act, c);
}

/* RFC 9002 7.7 / RFC 9000 8.1: a send needs BOTH the congestion window open and
 * the anti-amplification budget -- neither gate alone admits it. */
static int send_permitted(const quic_evloop *c)
{
    if (c->gate.phase != QUIC_CONNLOOP_ACTIVE) return 0;
    if (!quic_cwndctl_can_send(c->bytes_in_flight, c->cwnd, c->send_len))
        return 0;
    return antiamp_ok(c);
}

/* Emit one ack-eliciting packet under a fresh number, tracking it in flight. */
static void evloop_emit(quic_evloop *c)
{
    quic_connloop_on_send(&c->gate, c->level, 1, c->next_pn, c->send_len);
    c->next_pn++;
    c->bytes_in_flight += c->send_len;
}

/* RFC 9002 6: recovery before new data -- a pending retransmission is sent
 * first and new data is held back until the queue drains. */
static void emit_retransmit(quic_evloop *c)
{
    c->rtx_n--; /* consume the oldest queued retransmission */
    evloop_emit(c);
}

/* RFC 9002 6: with the gates open, recovery outranks new data. */
static void send_data(quic_evloop *c)
{
    if (c->rtx_n > 0) emit_retransmit(c);
    else if (c->have_new_data) evloop_emit(c);
}

/* Phase 3: prefer an owed ACK, then a retransmission, then new data; each
 * still subject to both send gates. */
static void phase_send(quic_evloop *c)
{
    if (!send_permitted(c)) return;
    if (c->ack_owed) { /* RFC 9000 13.2.1: ACK rides the next send */
        evloop_emit(c);
        c->ack_owed = 0;
        return;
    }
    send_data(c);
}

void quic_evloop_step(quic_evloop *c, u64 now)
{
    if (c->gate.phase == QUIC_CONNLOOP_CLOSED) return;
    phase_receive(c);
    phase_timers(c, now);
    phase_send(c);
}

/* Progress halts once closed; otherwise iterate up to the bound. */
static int step_done(const quic_evloop *c, usz i, usz max)
{
    return i >= max || c->gate.phase == QUIC_CONNLOOP_CLOSED;
}

void quic_evloop_run(quic_evloop *c, u64 now, usz max_iterations)
{
    usz i;
    for (i = 0; !step_done(c, i, max_iterations); i++)
        quic_evloop_step(c, now);
}

int quic_evloop_initiate_key_update(quic_evloop *c, u64 now)
{
    if (!quic_keyupdate_may_initiate(c->gate.handshake_confirmed,
                                     c->key_update_time, now, c->pto_period))
        return 0;
    c->key_generation++;       /* RFC 9001 6: advance the send generation */
    c->key_update_time = now;  /* retain the prior key for 3*PTO */
    return 1;
}

int quic_evloop_old_key_retained(const quic_evloop *c, u64 now)
{
    if (c->key_generation == 0) return 0; /* no prior generation exists yet */
    return quic_oldkey_retain(c->key_update_time, now, c->pto_period);
}

void quic_evloop_close(quic_evloop *c, int peer_closed)
{
    quic_connloop_close(&c->gate, peer_closed);
}
