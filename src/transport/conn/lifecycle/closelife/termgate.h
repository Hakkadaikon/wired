#ifndef CLOSELIFE_TERMGATE_H
#define CLOSELIFE_TERMGATE_H

#include "transport/conn/lifecycle/closelife/closelife.h"

/* RFC 9000 10.2: what a connection may put on the wire depends on its phase.
 * Open phases may send application data; closing may send ONLY a
 * CONNECTION_CLOSE; draining and closed send nothing at all. */
/** What life_send_kind permits sending in the connection's current
 * lifecycle phase. */
typedef enum {
  SEND_NONE = 0, /* nothing may be sent */
  SEND_CC,       /* only a CONNECTION_CLOSE may be sent */
  SEND_APPDATA   /* application data (and anything else) may be sent */
} send_kind;

/* The most that may be sent in the connection's current phase. */
send_kind life_send_kind(const life* l);

/* RFC 9000 10.2.1/10.2.2: the closing/draining period ends at exactly 3*PTO.
 * True iff phase is closing/draining AND the close timer has reached close_max
 * (never before). */
int life_close_due(const life* l);

/* RFC 9000 10.1: true iff open AND the idle timer has reached idle_max. */
int life_idle_due(const life* l);

#endif
