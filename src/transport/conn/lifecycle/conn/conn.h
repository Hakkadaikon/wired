#ifndef QUIC_CONN_CONN_H
#define QUIC_CONN_CONN_H

#include "common/platform/sys/syscall.h"

/** RFC 9000 handshake phase + connection lifecycle. Forward-only through the
 * open phases; any open phase may move to closing/draining, both -> closed. */
typedef enum {
  QUIC_PHASE_INITIAL = 0,
  QUIC_PHASE_HANDSHAKE,
  QUIC_PHASE_CONFIRMED,
  QUIC_PHASE_CLOSING,
  QUIC_PHASE_DRAINING,
  QUIC_PHASE_CLOSED
} phase;

/** Events that drive conn_step's phase transitions. */
typedef enum {
  QUIC_CONN_EV_HS_PROGRESS,  /* Initial -> Handshake */
  QUIC_CONN_EV_HS_CONFIRMED, /* Handshake -> Confirmed */
  QUIC_CONN_EV_CLOSE,        /* any open phase -> Closing */
  QUIC_CONN_EV_DRAIN,        /* any open phase -> Draining */
  QUIC_CONN_EV_CLOSED        /* Closing/Draining -> Closed */
} conn_event;

/** RFC 9000 12.3: three independent packet number spaces. */
typedef enum {
  QUIC_PN_INITIAL = 0,
  QUIC_PN_HANDSHAKE,
  QUIC_PN_APPLICATION,
  QUIC_PN_SPACE_COUNT
} pn_space;

/** A connection's phase plus the next packet number per space. Each space's
 * counter is strictly monotonic (next = last + 1), which by construction
 * forbids reuse and non-monotonic packet numbers. */
typedef struct {
  phase phase;
  u64   next_pn[QUIC_PN_SPACE_COUNT];
} conn;

/* Initialize a connection: Initial phase, all packet numbers start at 0. */
void conn_init(conn* c);

/* Apply ev to c->phase. Returns 1 if allowed (phase updated), 0 otherwise. */
int conn_step(conn* c, conn_event ev);

/* Allocate the next packet number in `space`, writing it to *pn and bumping
 * the counter. The Application space is refused before the handshake is
 * confirmed (RFC 9000 12.5). Returns 1 on success, 0 if refused. */
int conn_next_pn(conn* c, pn_space space, u64* pn);

#endif
