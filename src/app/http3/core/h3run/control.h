#ifndef H3RUN_CONTROL_H
#define H3RUN_CONTROL_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 6.2.1: each endpoint opens exactly one control stream, prefixed by
 * the stream type 0x00. A second control stream is H3_STREAM_CREATION_ERROR. */

/** RFC 9114 6.2.1: count of control streams seen, to catch a second one. */
typedef struct {
  u8 count; /* control streams seen on this connection */
} h3_control_state;

/* Write the control stream prefix (type 0x00) into buf. Returns bytes written
 * (1), or 0 if cap is too small. */
usz h3run_control_open(u8* buf, usz cap);

/* Record a control stream. Returns 1 for the first, 0 for any later one
 * (H3_STREAM_CREATION_ERROR). */
int h3_control_seen(h3_control_state* state);

#endif
