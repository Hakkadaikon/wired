#ifndef QUIC_FSM_FSM_H
#define QUIC_FSM_FSM_H

#include "common/platform/sys/syscall.h"

/* A small table-driven finite state machine shared by the stream and
 * connection state machines. A transition is legal iff some row names the
 * current (from, event) pair; applying it moves the state to that row's to. */

typedef struct { u8 from, ev, to; } quic_fsm_row;

#define QUIC_FSM_NONE 0xFF /* sentinel: no such transition */

/* Apply ev to *state using rows[0..count). On a matching row, set *state to
 * its `to` and return 1. Otherwise leave *state unchanged and return 0. */
int quic_fsm_step(u8 *state, const quic_fsm_row *rows, usz count, u8 ev);

#endif
