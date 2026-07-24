#include "transport/stream/data/stream/streamstate.h"

#include "transport/stream/data/stream/stream_id.h"
#include "transport/stream/data/stream/stream_role.h"

/* True when stream_id was initiated by the local (am_server) endpoint. */
static int locally_initiated(int am_server, u64 stream_id) {
  int client_initiated = quic_stream_is_client_initiated(stream_id);
  return (am_server != 0) == !client_initiated;
}

/* RFC 9000 2.1/3.1-3.2: whether the OTHER party (the client, from the local
 * am_server's point of view) can legitimately need to send (needs_send=1) or
 * receive (needs_send=0) on stream_id. Bidi streams place no restriction
 * either way; a uni stream permits data in only one direction. */
static int direction_ok(int am_server, u64 stream_id, int needs_send) {
  int other_is_client = am_server != 0; /* the peer of a server is a client */
  if (!quic_stream_is_uni(stream_id)) return 1; /* bidi: no restriction */
  return needs_send ? quic_stream_can_send(other_is_client, stream_id)
                    : quic_stream_can_receive(other_is_client, stream_id);
}

/* RFC 9000 3.2: a locally initiated stream not yet created (its type index
 * not below local_streams->opened) has no state to affect. A peer-initiated
 * stream needs no such check -- referencing it is what creates it. */
static int creation_ok(
    int am_server, u64 stream_id, const quic_streams* local_streams) {
  u64 index;
  if (!locally_initiated(am_server, stream_id)) return 1;
  index = stream_id >> 2;
  return index < local_streams->opened;
}

int quic_streamstate_ok(
    int                 am_server,
    u64                 stream_id,
    int                 needs_send,
    const quic_streams* local_streams) {
  if (!direction_ok(am_server, stream_id, needs_send)) return 0;
  return creation_ok(am_server, stream_id, local_streams);
}
