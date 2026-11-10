#ifndef FLOW_STREAMS_H
#define FLOW_STREAMS_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 4.6: an endpoint limits how many streams its peer may open of each
 * type via the initial_max_streams transport parameters and MAX_STREAMS
 * frames. The limit counts streams, not a byte offset. */

typedef struct {
  u64 limit;  /* maximum number of streams the peer may open */
  u64 opened; /* how many have been opened so far */
} streams;

#endif
