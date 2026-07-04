#ifndef QUIC_H3_PRIORITY_H
#define QUIC_H3_PRIORITY_H

#include "common/platform/sys/syscall.h"

/* RFC 9218 4. HTTP/3 Extensible Priorities: urgency (u, 0-7, default 3) and
 * incremental (i, 0/1, default 0). Lower urgency value is higher priority. */

#define QUIC_H3_URGENCY_DEFAULT 3
#define QUIC_H3_URGENCY_MAX 7

typedef struct {
  u8 urgency;     /* 0..7 */
  u8 incremental; /* 0 or 1 */
} quic_h3_priority;

void quic_h3_priority_init(quic_h3_priority* p);

/* True if urgency a outranks urgency b (smaller value = higher priority). */
int quic_h3_priority_higher(u8 urg_a, u8 urg_b);

int quic_h3_urgency_valid(u8 u);

#endif
