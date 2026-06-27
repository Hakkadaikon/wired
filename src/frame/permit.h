#ifndef QUIC_FRAME_PERMIT_H
#define QUIC_FRAME_PERMIT_H

#include "frame/dispatch.h"

/* RFC 9000 12.4 Table 3: which packet types each frame may appear in. The
 * four packet types are Initial, Handshake, 0-RTT, and 1-RTT (the "IH01"
 * columns). A frame in a packet type that does not permit it is a protocol
 * violation. */

typedef enum {
    QUIC_PKT_INITIAL = 0,
    QUIC_PKT_HANDSHAKE,
    QUIC_PKT_0RTT,
    QUIC_PKT_1RTT
} quic_packet_type;

/* Whether a frame of this kind is permitted in the given packet type. */
int quic_frame_permitted(quic_frame_kind kind, quic_packet_type pkt);

/* Whether a frame type value is a reserved/GREASE type to be ignored
 * (RFC 9000 12.4 / RFC 9287-style extension points: types of the form
 * 0x1f * N + 0x21). Such frames carry no semantics and must be tolerated. */
int quic_frame_is_grease(u64 type);

#endif
