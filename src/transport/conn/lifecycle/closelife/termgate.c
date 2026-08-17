#include "transport/conn/lifecycle/closelife/termgate.h"

/* RFC 9000 10.2: per-phase send capability. Indexed by life_phase:
 * open -> app data; closing -> CONNECTION_CLOSE only; draining/closed -> none.
 */
static const send_kind send_by_phase[] = {
    [LIFE_OPEN]     = SEND_APPDATA,
    [LIFE_CLOSING]  = SEND_CC,
    [LIFE_DRAINING] = SEND_NONE,
    [LIFE_CLOSED]   = SEND_NONE,
};

send_kind life_send_kind(const life* l) { return send_by_phase[l->phase]; }

/* The close timer only advances after entering closing/draining (close_ticks
 * starts and stays 0 otherwise, including an idle silent close), so reaching
 * close_max identifies the 3*PTO close deadline regardless of whether the tick
 * that hit the limit has already moved the phase to CLOSED. */
int life_close_due(const life* l) {
  return l->close_ticks > 0 && l->close_ticks >= l->close_max;
}

int life_idle_due(const life* l) {
  return l->phase == LIFE_OPEN && l->idle_ticks >= l->idle_max;
}
