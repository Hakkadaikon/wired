#ifndef QUIC_H3_PUSHID_H
#define QUIC_H3_PUSHID_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 4.6. The server may push a response only with a Push ID below the
 * maximum the client granted via MAX_PUSH_ID. The maximum starts at zero and
 * MAX_PUSH_ID may only raise it; a frame that would lower it is an error. */

typedef struct {
  u64 max; /* one past the greatest Push ID the client permits */
} quic_h3_push_state;

void quic_h3_push_init(quic_h3_push_state* s);

/* Apply a MAX_PUSH_ID value. Returns 1 if it raises (or holds) the maximum,
 * 0 if it would lower it (which the caller must treat as a connection error).
 */
int quic_h3_push_set_max(quic_h3_push_state* s, u64 max);

/* Whether a server push with this Push ID is permitted: id < max. */
int quic_h3_push_allowed(const quic_h3_push_state* s, u64 id);

#endif
