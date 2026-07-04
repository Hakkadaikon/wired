#ifndef QUIC_DGDELIVER_DG_RECV_H
#define QUIC_DGDELIVER_DG_RECV_H

#include "common/bytes/span/span.h"

/* RFC 9221 5: extract the payload of a received DATAGRAM frame (type 0x30 or
 * 0x31 at frame.p[0]) for delivery to the application. *payload points into
 * the frame buffer (a view, no copy). Returns 1 on success, 0 on a malformed
 * frame. */
int quic_dgdeliver_extract(quic_span frame, quic_span* payload);

#endif
