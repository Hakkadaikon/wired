#ifndef QUIC_EVLOOP_EVLOOP_H
#define QUIC_EVLOOP_EVLOOP_H

#include "transport/conn/loop/connloop/connloop.h"

/* RFC 9000 12 / RFC 9001 6 / RFC 9002 6: the steady-state event loop for one
 * connection. Each iteration runs three phases in a fixed order -- drain all
 * ready receives, then handle timers, then make one send decision -- delegating
 * every protocol judgement to the gating layer (connloop), the congestion
 * window, the anti-amplification budget, and the ACK/loss drivers. evloop only
 * orchestrates: it owns the cross-phase scratch state (pending receives, the
 * owed ACK, the retransmission queue, the congestion window, the key
 * generation) and feeds it through the existing components in order. */

#define QUIC_EVLOOP_QCAP 64

typedef struct {
    int ack_eliciting; /* RFC 9000 13.2.1: receiving this owes an ACK */
} quic_evloop_rx;

typedef struct {
    u64 pn;   /* original packet number of the lost packet */
    usz len;  /* its size, to re-send under a fresh number */
} quic_evloop_rtx;

typedef struct {
    int armed;
    u64 deadline; /* fires once now >= deadline */
} quic_evloop_timer;

typedef struct {
    quic_connloop gate; /* RFC 9000 12.2: send/recv/ack/pto/close gating */

    int level;          /* protection level the loop sends/receives at */
    u64 next_pn;        /* RFC 9002 A.1: monotonic, never reused */

    quic_evloop_rx rx[QUIC_EVLOOP_QCAP];
    usz rx_n;
    int ack_owed;       /* RFC 9000 13.2.1: an ACK is pending */

    quic_evloop_rtx rtx[QUIC_EVLOOP_QCAP];
    usz rtx_n;          /* RFC 9002 6: data awaiting retransmission */
    int have_new_data;  /* application has fresh data to originate */
    usz send_len;       /* bytes per outgoing packet */

    quic_evloop_timer pto;  /* RFC 9002 6.2 */
    quic_evloop_timer loss; /* RFC 9002 6.1 */
    quic_evloop_timer idle; /* RFC 9000 10.1 */

    u64 cwnd;            /* RFC 9002 7: congestion window in bytes */
    u64 bytes_in_flight; /* RFC 9002 B.2 */

    u64 key_generation;  /* RFC 9001 6: current send-key generation */
    u64 key_update_time; /* time the latest update started; for old-key retain */
    u64 pto_period;      /* RFC 9001 6.1: 3*PTO retention is measured against */
} quic_evloop;

/* Initialise an active loop at `level`, with `cwnd` open, `send_len`-byte
 * packets, and all timers disarmed. */
void quic_evloop_init(quic_evloop *c, int level, u64 cwnd, usz send_len);

/* Queue a received packet for processing inside the next step. */
void quic_evloop_on_receive(quic_evloop *c, int ack_eliciting);

/* Run one iteration: drain receives, handle timers, decide one send -- in that
 * order. A closed connection does nothing. */
void quic_evloop_step(quic_evloop *c, u64 now);

/* Repeat step until the connection is closed or `max_iterations` is reached. */
void quic_evloop_run(quic_evloop *c, u64 now, usz max_iterations);

/* RFC 9001 6.1: begin a key update -- only once 1-RTT is confirmed. Advances
 * the generation and retains the prior one. Returns 1 if started, 0 if barred.
 */
int quic_evloop_initiate_key_update(quic_evloop *c, u64 now);

/* RFC 9001 6.1: 1 while the previous generation's key is still retained
 * (within 3*PTO of the last update), 0 once it may be discarded. */
int quic_evloop_old_key_retained(const quic_evloop *c, u64 now);

/* RFC 9000 10.2: begin closing. Once left, the active phase never returns. */
void quic_evloop_close(quic_evloop *c, int peer_closed);

#endif
