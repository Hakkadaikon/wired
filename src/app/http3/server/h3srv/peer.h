#ifndef WIRED_H3SRV_PEER_H
#define WIRED_H3SRV_PEER_H

#include "app/http3/server/h3srv/state.h"
#include "common/platform/sys/syscall.h"

/* RFC 9114 6.2 / RFC 9204 4.2. Accept a peer unidirectional stream by its type
 * (0x00 control, 0x02 QPACK encoder, 0x03 QPACK decoder). Returns 1 for any of
 * these recognised types (no connection error), 0 otherwise. */
int wired_h3srv_accept_uni(u64 stream_type);

/* RFC 9204 4.2. Record a peer QPACK encoder/decoder unidirectional stream.
 * Returns 1 and marks the corresponding peer_qpack_* flag on the first
 * instance of either stream type. On a second instance of the SAME type,
 * returns 0 and sets *err to H3_STREAM_CREATION_ERROR. Any other stream_type
 * (not the QPACK encoder or decoder type) is a no-op that returns 1 with
 * *err left 0. */
int wired_h3srv_on_peer_qpack(wired_h3srv_state* st, u64 stream_type, u16* err);

#endif
