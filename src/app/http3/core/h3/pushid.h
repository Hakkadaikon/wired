#ifndef QUIC_H3_PUSHID_H
#define QUIC_H3_PUSHID_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 4.6. The server may push a response only with a Push ID below the
 * maximum the client granted via MAX_PUSH_ID. The maximum starts at zero and
 * MAX_PUSH_ID may only raise it; a frame that would lower it is an error. */

/** RFC 9114 4.6: the client's granted Push ID range for this connection. */
typedef struct {
  u64 max; /* one past the greatest Push ID the client permits */
} h3_push_state;

void h3_push_init(h3_push_state* s);

/* Apply a MAX_PUSH_ID value. Returns 1 if it raises (or holds) the maximum,
 * 0 if it would lower it (which the caller must treat as a connection error).
 */
int h3_push_set_max(h3_push_state* s, u64 max);

/* Whether a server push with this Push ID is permitted: id < max. */
int h3_push_allowed(const h3_push_state* s, u64 id);

/* RFC 9114 7.2.3: a received CANCEL_PUSH is valid only if its Push ID is one
 * the client has actually granted room for (id < s->max, the same bound
 * h3_push_allowed enforces for an outgoing PUSH_PROMISE) -- a Push ID
 * at or past the client's MAX_PUSH_ID was never a Push ID this connection
 * could have used, so referencing it is a connection error of type
 * H3_ID_ERROR. Returns 1 if the Push ID is in range, 0 if the receiver must
 * close with H3_ID_ERROR. */
int h3_push_cancel_ok(const h3_push_state* s, u64 id);

#endif
