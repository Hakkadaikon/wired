#include "h3recv/req_frames.h"
#include "h3/frame.h"

int quic_h3req_recv_first_headers(const u8 *stream, usz len,
                                  const u8 **field_section, usz *fs_len)
{
    u64 type, plen;
    const u8 *payload;
    /* RFC 9114 4.1: the first frame on a request stream is HEADERS. */
    if (quic_h3_frame_get(stream, len, &type, &payload, &plen) == 0) return 0;
    if (type != QUIC_H3_FRAME_HEADERS) return 0;
    *field_section = payload;
    *fs_len = (usz)plen;
    return 1;
}
