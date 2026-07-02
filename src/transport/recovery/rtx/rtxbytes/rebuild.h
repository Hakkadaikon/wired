#ifndef QUIC_RTXBYTES_REBUILD_H
#define QUIC_RTXBYTES_REBUILD_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9002 13.3: when a packet is lost, frames it carried are retransmitted
 * in a new packet, except ACK and PADDING frames, which are not
 * retransmittable. Rebuild copies a retransmittable lost frame verbatim into
 * out; a non-retransmittable frame yields *out_len = 0 (skip it). */

/* Returns 1 if the lost frame is retransmittable and was copied (out->len
 * set), or skipped (out->len 0). Returns 0 on a malformed type or
 * insufficient out capacity. */
int quic_rtxbytes_rebuild(quic_span lost_frame, quic_obuf *out);

/* RFC 9002 13.3: every frame type except ACK (0x02/0x03) and PADDING (0x00)
 * is retransmittable. Returns 1 if the frame at buf (len bytes) is
 * retransmittable, 0 if not, and -1 if the type varint is malformed. */
int quic_rtxbytes_retransmittable(const u8 *buf, usz len);

#endif
