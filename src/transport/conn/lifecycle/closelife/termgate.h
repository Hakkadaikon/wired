#ifndef QUIC_CLOSELIFE_TERMGATE_H
#define QUIC_CLOSELIFE_TERMGATE_H

#include "transport/conn/lifecycle/closelife/closelife.h"

/* RFC 9000 10.2: what a connection may put on the wire depends on its phase.
 * Open phases may send application data; closing may send ONLY a
 * CONNECTION_CLOSE; draining and closed send nothing at all. */
typedef enum {
  QUIC_SEND_NONE = 0, /* nothing may be sent */
  QUIC_SEND_CC,       /* only a CONNECTION_CLOSE may be sent */
  QUIC_SEND_APPDATA   /* application data (and anything else) may be sent */
} quic_send_kind;

/* The most that may be sent in the connection's current phase. */
quic_send_kind quic_life_send_kind(const quic_life* l);

/* RFC 9000 10.2.1/10.2.2: the closing/draining period ends at exactly 3*PTO.
 * True iff phase is closing/draining AND the close timer has reached close_max
 * (never before). */
int quic_life_close_due(const quic_life* l);

/* RFC 9000 10.1: true iff open AND the idle timer has reached idle_max. */
int quic_life_idle_due(const quic_life* l);

#endif
