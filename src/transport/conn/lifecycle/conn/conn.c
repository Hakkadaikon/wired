#include "transport/conn/lifecycle/conn/conn.h"

#include "transport/conn/lifecycle/fsm/fsm.h"

/* RFC 9000 phase + lifecycle. Forward only through open phases; any open
 * phase may close or drain; both converge to Closed. Closed never reopens. */
static const fsm_row phase_rows[] = {
    {PHASE_INITIAL, CONN_EV_HS_PROGRESS, PHASE_HANDSHAKE},
    {PHASE_HANDSHAKE, CONN_EV_HS_CONFIRMED, PHASE_CONFIRMED},
    {PHASE_INITIAL, CONN_EV_CLOSE, PHASE_CLOSING},
    {PHASE_HANDSHAKE, CONN_EV_CLOSE, PHASE_CLOSING},
    {PHASE_CONFIRMED, CONN_EV_CLOSE, PHASE_CLOSING},
    {PHASE_INITIAL, CONN_EV_DRAIN, PHASE_DRAINING},
    {PHASE_HANDSHAKE, CONN_EV_DRAIN, PHASE_DRAINING},
    {PHASE_CONFIRMED, CONN_EV_DRAIN, PHASE_DRAINING},
    {PHASE_CLOSING, CONN_EV_CLOSED, PHASE_CLOSED},
    {PHASE_DRAINING, CONN_EV_CLOSED, PHASE_CLOSED},
};

void conn_init(conn* c) {
  c->phase = PHASE_INITIAL;
  for (usz i = 0; i < PN_SPACE_COUNT; i++) c->next_pn[i] = 0;
}

int conn_step(conn* c, conn_event ev) {
  u8        st    = (u8)c->phase;
  fsm_table table = {phase_rows, sizeof(phase_rows) / sizeof(phase_rows[0])};
  int       ok    = fsm_step(&st, &table, (u8)ev);
  c->phase        = (phase)st;
  return ok;
}

/* The Application space may only be used once the handshake is confirmed
 * (and while the connection is still open). */
static int app_space_allowed(const conn* c, pn_space space) {
  if (space != PN_APPLICATION) return 1;
  return c->phase == PHASE_CONFIRMED;
}

int conn_next_pn(conn* c, pn_space space, u64* pn) {
  if (!app_space_allowed(c, space)) return 0;
  *pn = c->next_pn[space];
  c->next_pn[space] += 1; /* strictly monotonic: no reuse, no regress */
  return 1;
}
