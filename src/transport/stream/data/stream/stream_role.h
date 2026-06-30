#ifndef QUIC_STREAM_STREAM_ROLE_H
#define QUIC_STREAM_STREAM_ROLE_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 3.1/2.1: a unidirectional stream may only be written by the
 * endpoint that initiated it; the peer may only read it. Bidirectional
 * streams may be both sent on and received on by either endpoint.
 *
 * am_client is non-zero when the local endpoint is the client. */

/* True if the local endpoint may send on the given stream. */
int quic_stream_can_send(int am_client, u64 stream_id);

/* True if the local endpoint may receive on the given stream. */
int quic_stream_can_receive(int am_client, u64 stream_id);

#endif
