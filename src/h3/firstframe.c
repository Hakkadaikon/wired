#include "h3/firstframe.h"
#include "h3/frame.h"

/* RFC 9114 6.2.1 */
int quic_h3_first_frame_ok(int stream_kind, u64 frame_type)
{
    if (stream_kind == QUIC_H3_STREAM_KIND_CONTROL)
        return frame_type == QUIC_H3_FRAME_SETTINGS;
    if (stream_kind == QUIC_H3_STREAM_KIND_REQUEST)
        return frame_type == QUIC_H3_FRAME_HEADERS;
    return 0;
}
