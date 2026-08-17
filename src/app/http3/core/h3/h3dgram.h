#ifndef H3_DGRAM_H
#define H3_DGRAM_H

#include "common/platform/sys/syscall.h"

/* RFC 9114. An HTTP/3 datagram carries a Quarter Stream ID: the stream ID of
 * the associated request stream divided by four. Since request streams are
 * client-initiated bidirectional, their IDs are multiples of four, so the
 * division is exact and reversible. */

u64 h3_quarter_stream_id(u64 stream_id);
u64 h3_stream_from_quarter(u64 quarter);

#endif
