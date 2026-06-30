#include "appdata/stream_send.h"
#include "transport/packet/frame/frame/frame.h"

/* RFC 9000 19.8 */
int quic_appdata_stream_frame(u64 stream_id, u64 offset,
                              const u8 *data, usz len, int fin,
                              u8 *out, usz cap, usz *out_len)
{
    quic_stream_frame f;
    f.stream_id = stream_id;
    f.offset = offset;
    f.length = len;
    f.data = data;
    f.fin = fin ? 1 : 0;
    usz n = quic_frame_put_stream(out, cap, &f);
    if (n == 0) return 0;
    *out_len = n;
    return 1;
}
