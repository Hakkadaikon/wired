#ifndef H3_PRIUPDATE_H
#define H3_PRIUPDATE_H

#include "app/http3/core/h3/priority.h"
#include "common/bytes/span/span.h"

/** @file
 * RFC 9218 7: the PRIORITY_UPDATE frame — a client reprioritizes a request
 * (type 0x0F0700) or push (0x0F0701) element by carrying its id and a
 * Priority Field Value, plus the RFC 8941-shaped dictionary parser for that
 * value (`u=0..7`, `i`). */

#define H3_FRAME_PRIORITY_UPDATE 0x0F0700
#define H3_FRAME_PRIORITY_UPDATE_PUSH 0x0F0701

/** RFC 9218 7: a decoded PRIORITY_UPDATE frame. */
typedef struct {
  int        push;       /**< 0: request variant, 1: push variant */
  u64        element_id; /**< prioritized element (stream or push) id */
  wired_span value;      /**< Priority Field Value bytes (view) */
} h3_priupdate;

/** Encode one PRIORITY_UPDATE frame.
 * @return bytes written, 0 on overflow. */
usz h3_priupdate_put(u8* buf, usz cap, const h3_priupdate* f);

/** Decode a PRIORITY_UPDATE frame at buf (value views into buf).
 * @return bytes consumed, 0 on a different type or truncated input. */
usz h3_priupdate_get(wired_span buf, h3_priupdate* f);

/** Parse a Priority Field Value, an RFC 8941 Dictionary, into p (RFC 9218
 * 4/5/7): an Integer `u=0..7` sets the urgency, a Boolean `i` the
 * incremental flag; an unknown key, or a value out of range or of another
 * type, is ignored, and a value that is not a valid Dictionary leaves the
 * RFC defaults (u=3, i=0) as a whole. */
void h3_priority_sfv(wired_span v, h3_priority* p);

#endif
