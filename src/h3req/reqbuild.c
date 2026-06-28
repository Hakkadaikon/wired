#include "h3req/reqbuild.h"
#include "h3/frame.h"

/* Append a DATA frame at *off when there is a body; *off is left unchanged
 * for an empty body. Returns 1 ok, 0 if out lacks capacity. */
static int append_body(const u8 *body, usz body_len, u8 *out, usz cap,
                       usz *off)
{
    usz n;
    if (!body_len) return 1;
    n = quic_h3_frame_put(out + *off, cap - *off, QUIC_H3_FRAME_DATA,
                          body, body_len);
    *off += n;
    return n != 0;
}

/* RFC 9114 4.1 */
int quic_h3req_build(const u8 *qpack_headers, usz h_len,
                     const u8 *body, usz body_len,
                     u8 *out, usz cap, usz *out_len)
{
    usz off = quic_h3_frame_put(out, cap, QUIC_H3_FRAME_HEADERS,
                                qpack_headers, h_len);
    if (!off) return 0;
    if (!append_body(body, body_len, out, cap, &off)) return 0;
    *out_len = off;
    return 1;
}
