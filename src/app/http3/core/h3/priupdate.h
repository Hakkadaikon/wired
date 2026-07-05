#ifndef QUIC_H3_PRIUPDATE_H
#define QUIC_H3_PRIUPDATE_H

#include "app/http3/core/h3/priority.h"
#include "common/bytes/span/span.h"

/** @file
 * RFC 9218 7: the PRIORITY_UPDATE frame — a client reprioritizes a request
 * (type 0x0F0700) or push (0x0F0701) element by carrying its id and a
 * Priority Field Value, plus the RFC 8941-shaped dictionary parser for that
 * value (`u=0..7`, `i`). */

#define QUIC_H3_FRAME_PRIORITY_UPDATE 0x0F0700
#define QUIC_H3_FRAME_PRIORITY_UPDATE_PUSH 0x0F0701

typedef struct {
  int       push;       /**< 0: request variant, 1: push variant */
  u64       element_id; /**< prioritized element (stream or push) id */
  quic_span value;      /**< Priority Field Value bytes (view) */
} quic_h3_priupdate;

/** Encode one PRIORITY_UPDATE frame.
 * @return bytes written, 0 on overflow. */
usz quic_h3_priupdate_put(u8* buf, usz cap, const quic_h3_priupdate* f);

/** Decode a PRIORITY_UPDATE frame at buf (value views into buf).
 * @return bytes consumed, 0 on a different type or truncated input. */
usz quic_h3_priupdate_get(quic_span buf, quic_h3_priupdate* f);

/** Parse a Priority Field Value dictionary into p (RFC 9218 4/5): `u=0..7`
 * sets the urgency, `i`/`i=?1` the incremental flag; anything malformed or
 * unknown leaves the RFC defaults (u=3, i=0) in place. */
void quic_h3_priority_sfv(quic_span v, quic_h3_priority* p);

#endif
