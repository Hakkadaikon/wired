#include "transport/conn/lifecycle/conn/conn.h"

#include "transport/conn/lifecycle/fsm/fsm.h"

/* RFC 9000 phase + lifecycle. Forward only through open phases; any open
 * phase may close or drain; both converge to Closed. Closed never reopens. */
static const quic_fsm_row phase_rows[] = {
    {QUIC_PHASE_INITIAL, QUIC_CONN_EV_HS_PROGRESS, QUIC_PHASE_HANDSHAKE},
    {QUIC_PHASE_HANDSHAKE, QUIC_CONN_EV_HS_CONFIRMED, QUIC_PHASE_CONFIRMED},
    {QUIC_PHASE_INITIAL, QUIC_CONN_EV_CLOSE, QUIC_PHASE_CLOSING},
    {QUIC_PHASE_HANDSHAKE, QUIC_CONN_EV_CLOSE, QUIC_PHASE_CLOSING},
    {QUIC_PHASE_CONFIRMED, QUIC_CONN_EV_CLOSE, QUIC_PHASE_CLOSING},
    {QUIC_PHASE_INITIAL, QUIC_CONN_EV_DRAIN, QUIC_PHASE_DRAINING},
    {QUIC_PHASE_HANDSHAKE, QUIC_CONN_EV_DRAIN, QUIC_PHASE_DRAINING},
    {QUIC_PHASE_CONFIRMED, QUIC_CONN_EV_DRAIN, QUIC_PHASE_DRAINING},
    {QUIC_PHASE_CLOSING, QUIC_CONN_EV_CLOSED, QUIC_PHASE_CLOSED},
    {QUIC_PHASE_DRAINING, QUIC_CONN_EV_CLOSED, QUIC_PHASE_CLOSED},
};

void quic_conn_init(quic_conn *c) {
  c->phase = QUIC_PHASE_INITIAL;
  for (usz i = 0; i < QUIC_PN_SPACE_COUNT; i++) c->next_pn[i] = 0;
}

int quic_conn_step(quic_conn *c, quic_conn_event ev) {
  u8  st = (u8)c->phase;
  int ok = quic_fsm_step(
      &st, phase_rows, sizeof(phase_rows) / sizeof(phase_rows[0]), (u8)ev);
  c->phase = (quic_phase)st;
  return ok;
}

/* The Application space may only be used once the handshake is confirmed
 * (and while the connection is still open). */
static int app_space_allowed(const quic_conn *c, quic_pn_space space) {
  if (space != QUIC_PN_APPLICATION) return 1;
  return c->phase == QUIC_PHASE_CONFIRMED;
}

int quic_conn_next_pn(quic_conn *c, quic_pn_space space, u64 *pn) {
  if (!app_space_allowed(c, space)) return 0;
  *pn = c->next_pn[space];
  c->next_pn[space] += 1; /* strictly monotonic: no reuse, no regress */
  return 1;
}
