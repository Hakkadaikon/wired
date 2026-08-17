#ifndef FSM_FSM_H
#define FSM_FSM_H

#include "common/platform/sys/syscall.h"

/* A small table-driven finite state machine shared by the stream and
 * connection state machines. A transition is legal iff some row names the
 * current (from, event) pair; applying it moves the state to that row's to. */

/** One legal transition: from state `from` on event `ev`, move to `to`. */
typedef struct {
  u8 from, ev, to;
} fsm_row;

/** A transition table: rows[0..count). */
typedef struct {
  const fsm_row* rows;
  usz            count;
} fsm_table;

#define FSM_NONE 0xFF /* sentinel: no such transition */

/* Apply ev to *state using `table`. On a matching row, set *state to its `to`
 * and return 1. Otherwise leave *state unchanged and return 0. */
int fsm_step(u8* state, const fsm_table* table, u8 ev);

#endif
