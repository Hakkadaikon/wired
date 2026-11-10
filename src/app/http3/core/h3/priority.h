#ifndef H3_PRIORITY_H
#define H3_PRIORITY_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9218 4. HTTP/3 Extensible Priorities: urgency (u, 0-7, default 3) and
 * incremental (i, 0/1, default 0). Lower urgency value is higher priority. */

#define H3_URGENCY_DEFAULT 3
#define H3_URGENCY_MAX 7

/** RFC 9218 4: a request's priority — urgency (lower is more urgent) and
 * whether the response may be served incrementally. */
typedef struct {
  u8 urgency;     /**< 0..7, default 3 */
  u8 incremental; /**< 0 or 1, default 0 */
} h3_priority;

void h3_priority_init(h3_priority* p);

#endif
