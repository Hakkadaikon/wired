#include "transport/stream/flow/flowviol/closeframe.h"
#include "transport/packet/frame/frame/frame.h"

/* RFC 9000 19.19 */
int quic_flowviol_close_frame(u64 error_code, u64 frame_type,
                              const u8 *reason, usz reason_len,
                              u8 *out, usz cap, usz *out_len)
{
    quic_conn_close_frame f;
    usz n;
    f.is_app = 0;
    f.error_code = error_code;
    f.frame_type = frame_type;
    f.reason_len = (u64)reason_len;
    f.reason = reason;
    n = quic_frame_put_conn_close(out, cap, &f);
    if (n == 0) return 0;
    *out_len = n;
    return 1;
}
