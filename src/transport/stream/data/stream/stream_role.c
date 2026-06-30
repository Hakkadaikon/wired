#include "transport/stream/data/stream/stream_role.h"
#include "transport/stream/data/stream/stream_id.h"

/* RFC 9000 2.1: the local endpoint initiated the stream when its role
 * matches the stream's initiator bit. */
static int am_initiator(int am_client, u64 stream_id)
{
    return (am_client != 0) == (quic_stream_is_client_initiated(stream_id) != 0);
}

int quic_stream_can_send(int am_client, u64 stream_id)
{
    if (!quic_stream_is_uni(stream_id)) return 1; /* bidi: either side sends */
    return am_initiator(am_client, stream_id);    /* uni: only the initiator */
}

int quic_stream_can_receive(int am_client, u64 stream_id)
{
    if (!quic_stream_is_uni(stream_id)) return 1;  /* bidi: either side receives */
    return !am_initiator(am_client, stream_id);    /* uni: only the peer reads */
}
