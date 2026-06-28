#include "h3resp/resp_build.h"
#include "h3resp/field_encode.h"
#include "h3/frame.h"

/* Append a DATA frame at *off when there is a body; *off is left unchanged for
 * an empty body. Returns 1 ok, 0 if out lacks capacity. */
static int resp_append_body(const u8 *body, usz body_len, u8 *out, usz cap, usz *off)
{
    usz n;
    if (!body_len) return 1;
    n = quic_h3_frame_put(out + *off, cap - *off, QUIC_H3_FRAME_DATA,
                          body, body_len);
    *off += n;
    return n != 0;
}

/* Emit the HEADERS frame carrying the :status field section. Returns its byte
 * length at *off, or 0 if encoding or framing lacks capacity. */
static usz put_headers(u16 status, u8 *out, usz cap)
{
    u8 field[16];
    usz flen;
    if (!quic_h3resp_encode_status(status, field, sizeof field, &flen))
        return 0;
    return quic_h3_frame_put(out, cap, QUIC_H3_FRAME_HEADERS, field, flen);
}

/* RFC 9114 4.1 */
int quic_h3resp_build(u16 status, const u8 *body, usz body_len,
                      u8 *out, usz cap, usz *out_len)
{
    usz off = put_headers(status, out, cap);
    if (!off) return 0;
    if (!resp_append_body(body, body_len, out, cap, &off)) return 0;
    *out_len = off;
    return 1;
}
