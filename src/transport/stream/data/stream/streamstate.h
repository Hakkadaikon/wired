#ifndef QUIC_STREAM_STREAMSTATE_H
#define QUIC_STREAM_STREAMSTATE_H

#include "transport/stream/flow/flow/streams.h"

/* RFC 9000 19.4/19.5/19.8/19.10/19.13: a stream-affecting frame (RESET_STREAM,
 * STOP_SENDING, STREAM, MAX_STREAM_DATA, STREAM_DATA_BLOCKED) must reference a
 * stream the addressed party can act on:
 *
 *  - directionality: a unidirectional stream carries data in only one
 *    direction; a frame requiring the "other" party to send on a stream that
 *    is unidirectional away from them is invalid regardless of creation
 *    state.
 *  - creation: a stream initiated by the local (server) endpoint that has not
 *    been created yet (its type index is not below local_streams->opened) has
 *    no state at all to affect. A peer-initiated stream has no such check --
 *    referencing it is itself what creates it (RFC 9000 3.2).
 *
 * Either violation is a STREAM_STATE_ERROR. */

/* Whether stream_id may legitimately be referenced by a frame that requires
 * the addressed party (the party OTHER than am_server, i.e. the client) to
 * be able to send on it (needs_send=1) or receive on it (needs_send=0).
 * local_streams tracks how many of the LOCAL (am_server) endpoint's own
 * streams of stream_id's type have been created so far; only consulted when
 * stream_id is locally initiated. Returns 1 if legal, 0 (STREAM_STATE_ERROR)
 * otherwise. */
int quic_streamstate_ok(
    int                 am_server,
    u64                 stream_id,
    int                 needs_send,
    const quic_streams* local_streams);

#endif
