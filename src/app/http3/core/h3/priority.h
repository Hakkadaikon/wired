#ifndef QUIC_H3_PRIORITY_H
#define QUIC_H3_PRIORITY_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9218 4. HTTP/3 Extensible Priorities: urgency (u, 0-7, default 3) and
 * incremental (i, 0/1, default 0). Lower urgency value is higher priority. */

#define QUIC_H3_URGENCY_DEFAULT 3
#define QUIC_H3_URGENCY_MAX 7

/** RFC 9218 4: a request's priority — urgency (lower is more urgent) and
 * whether the response may be served incrementally. */
typedef struct {
  u8 urgency;     /**< 0..7, default 3 */
  u8 incremental; /**< 0 or 1, default 0 */
} quic_h3_priority;

void quic_h3_priority_init(quic_h3_priority* p);

/* True if urgency a outranks urgency b (smaller value = higher priority). */
int quic_h3_priority_higher(u8 urg_a, u8 urg_b);

int quic_h3_urgency_valid(u8 u);

/* RFC 9218 4.1: take an ASCII digit '0'..'7' as the urgency; anything else
 * leaves p untouched. */
void quic_h3_priority_set_urgency(quic_h3_priority* p, u8 digit);

/* RFC 9218 4.2: at an `i` member starting at v[i], a bare `i` (or `i=?1`)
 * sets incremental, `i=?0` clears it; malformed forms leave p untouched. */
void quic_h3_priority_set_incremental(quic_h3_priority* p, quic_span v, usz i);

#endif
