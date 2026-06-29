#include "closelife/closelife.h"

void quic_life_init(quic_life *l, u64 idle_max, u64 close_max)
{
    l->phase = QUIC_LIFE_OPEN;
    l->idle_ticks = 0;
    l->idle_max = idle_max;
    l->close_ticks = 0;
    l->close_max = close_max;
    l->sent_close = 0;
    l->notified = 0;
}

/* While open, idle ticks accumulate and a silent close fires at the limit. */
static void tick_open(quic_life *l)
{
    l->idle_ticks += 1;
    if (l->idle_ticks >= l->idle_max) l->phase = QUIC_LIFE_CLOSED;
}

/* In CLOSING/DRAINING, the close timer counts toward CLOSED. */
static void tick_closing(quic_life *l)
{
    l->close_ticks += 1;
    if (l->close_ticks >= l->close_max) l->phase = QUIC_LIFE_CLOSED;
}

/* CLOSED is terminal; OPEN idles; CLOSING/DRAINING drain to CLOSED. */
void quic_life_tick(quic_life *l)
{
    if (l->phase == QUIC_LIFE_OPEN) tick_open(l);
    else if (l->phase == QUIC_LIFE_CLOSED) return;
    else tick_closing(l);
}

void quic_life_on_recv(quic_life *l)
{
    if (l->phase == QUIC_LIFE_OPEN) l->idle_ticks = 0;
}

void quic_life_on_send(quic_life *l)
{
    if (l->phase == QUIC_LIFE_OPEN) l->idle_ticks = 0;
}

void quic_life_close(quic_life *l)
{
    if (l->phase != QUIC_LIFE_OPEN) return; /* one-way; no reopen */
    l->phase = QUIC_LIFE_CLOSING;
    l->sent_close = 1;
    l->close_ticks = 0;
    l->notified = 1; /* notify app once: guard above makes this single-shot */
}

void quic_life_on_peer_close(quic_life *l)
{
    if (l->phase != QUIC_LIFE_OPEN) return;
    l->phase = QUIC_LIFE_DRAINING;
    l->close_ticks = 0;
    l->notified = 1; /* peer close: notify app once (single-shot via guard) */
}

void quic_life_on_reset(quic_life *l)
{
    if (l->phase != QUIC_LIFE_CLOSED) l->phase = QUIC_LIFE_CLOSED;
}
