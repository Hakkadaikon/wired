#include "transport/conn/lifecycle/closelife/termgate.h"

/* RFC 9000 10.2: per-phase send capability. Indexed by quic_life_phase:
 * open -> app data; closing -> CONNECTION_CLOSE only; draining/closed -> none. */
static const quic_send_kind send_by_phase[] = {
    [QUIC_LIFE_OPEN]     = QUIC_SEND_APPDATA,
    [QUIC_LIFE_CLOSING]  = QUIC_SEND_CC,
    [QUIC_LIFE_DRAINING] = QUIC_SEND_NONE,
    [QUIC_LIFE_CLOSED]   = QUIC_SEND_NONE,
};

quic_send_kind quic_life_send_kind(const quic_life *l)
{
    return send_by_phase[l->phase];
}

/* The close timer only advances after entering closing/draining (close_ticks
 * starts and stays 0 otherwise, including an idle silent close), so reaching
 * close_max identifies the 3*PTO close deadline regardless of whether the tick
 * that hit the limit has already moved the phase to CLOSED. */
int quic_life_close_due(const quic_life *l)
{
    return l->close_ticks > 0 && l->close_ticks >= l->close_max;
}

int quic_life_idle_due(const quic_life *l)
{
    return l->phase == QUIC_LIFE_OPEN && l->idle_ticks >= l->idle_max;
}
