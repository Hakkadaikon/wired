#ifndef QUIC_CLOSELIFE_CLOSELIFE_H
#define QUIC_CLOSELIFE_CLOSELIFE_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 10: connection close lifecycle driven by timer ticks and
 * CONNECTION_CLOSE / stateless-reset events. The open phases (Initial,
 * Handshake, Confirmed) are collapsed into one "open" state here; from there
 * the connection moves one-way to CLOSING, DRAINING, or CLOSED and never
 * reopens. CLOSED is a stable terminal. */

typedef enum {
    QUIC_LIFE_OPEN = 0,
    QUIC_LIFE_CLOSING,
    QUIC_LIFE_DRAINING,
    QUIC_LIFE_CLOSED
} quic_life_phase;

typedef struct {
    quic_life_phase phase;
    u64 idle_ticks;     /* counts up while open; fires at idle_max */
    u64 idle_max;       /* max_idle_timeout in ticks */
    u64 close_ticks;    /* counts up in CLOSING/DRAINING; fires at close_max */
    u64 close_max;      /* 3*PTO in ticks */
    u8  sent_close;     /* we sent a CONNECTION_CLOSE */
    u8  notified;       /* app told of the close, exactly once on close path */
} quic_life;

void quic_life_init(quic_life *l, u64 idle_max, u64 close_max);

/* Advance one timer tick: open idles toward a silent close; CLOSING/DRAINING
 * count toward CLOSED. */
void quic_life_tick(quic_life *l);

/* A (non-reset) packet was received: reset the idle timer while open. */
void quic_life_on_recv(quic_life *l);

/* RFC 9000 10.1: an ack-eliciting packet was sent: reset the idle timer while
 * open. */
void quic_life_on_send(quic_life *l);

/* The application starts an immediate close: send CONNECTION_CLOSE, enter
 * CLOSING. No effect once past open. */
void quic_life_close(quic_life *l);

/* A CONNECTION_CLOSE was received from the peer: enter DRAINING. */
void quic_life_on_peer_close(quic_life *l);

/* A stateless reset was detected: go straight to CLOSED. */
void quic_life_on_reset(quic_life *l);

#endif
