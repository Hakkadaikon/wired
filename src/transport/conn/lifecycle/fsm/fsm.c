#include "transport/conn/lifecycle/fsm/fsm.h"

/* True if r names the transition keyed by (from, ev). */
static int row_matches(const quic_fsm_row *r, u8 from, u8 ev) {
  return r->from == from && r->ev == ev;
}

/* Look up (from, ev). Returns the target state, or QUIC_FSM_NONE if absent. */
static u8 lookup(const quic_fsm_row *rows, usz count, u8 from, u8 ev) {
  for (usz i = 0; i < count; i++)
    if (row_matches(&rows[i], from, ev)) return rows[i].to;
  return QUIC_FSM_NONE;
}

int quic_fsm_step(u8 *state, const quic_fsm_row *rows, usz count, u8 ev) {
  u8 to = lookup(rows, count, *state, ev);
  if (to == QUIC_FSM_NONE) return 0;
  *state = to;
  return 1;
}
