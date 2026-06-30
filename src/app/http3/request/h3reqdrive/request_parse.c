#include "app/http3/request/h3reqdrive/request_parse.h"
#include "app/http3/core/h3/frame.h"
#include "frame/frame.h"

/* RFC 9114 9 / 7.2.8: walk the request stream's HTTP/3 frames, skipping any
 * unknown/reserved frame (e.g. the GREASE frame curl/quiche send), until the
 * HEADERS frame is found; view its field-section payload in place. Returns 1
 * if a HEADERS frame is reached, 0 if the stream ends or is truncated. */
static int find_headers(const u8 *h3, usz n, const u8 **fs, usz *fs_len,
                        usz *end)
{
    u64 type = 0, plen = 0;
    usz off = 0;
    while (type != QUIC_H3_FRAME_HEADERS) {
        usz used = quic_h3_frame_get(h3 + off, n - off, &type, fs, &plen);
        if (!used)
            return 0;
        off += used;
    }
    *fs_len = (usz)plen;
    *end = off;
    return 1;
}

/* Decode the frame at *off; on a DATA frame view its body into r and stop.
 * Returns 1 when DATA is found (*off advanced past it is irrelevant then), 0
 * on a truncated/undecodable frame, -1 to keep walking (a skipped frame). */
static int body_step(const u8 *h3, usz n, usz *off, quic_h3reqdrive_req *r)
{
    u64 type = 0, plen = 0;
    const u8 *pl = 0;
    usz used = quic_h3_frame_get(h3 + *off, n - *off, &type, &pl, &plen);
    if (!used)
        return 0;
    *off += used;
    if (type != QUIC_H3_FRAME_DATA)
        return -1;
    r->body = pl;
    r->body_len = (usz)plen;
    return 1;
}

/* RFC 9114 4.1 / 9: view the request body from the first DATA frame after
 * HEADERS, walking past any interleaved unknown/GREASE frame (curl does not
 * place DATA immediately after HEADERS). Reaching the stream end with no DATA
 * is a bodyless request (GET): leave the view empty and succeed. A truncated
 * remainder fails. A request split across multiple DATA frames is not joined
 * (curl/typical clients send one). */
static int find_body(const u8 *h3, usz n, usz off, quic_h3reqdrive_req *r)
{
    while (off < n) {
        int s = body_step(h3, n, &off, r);
        if (s >= 0)
            return s;
    }
    return 1;
}

int quic_h3reqdrive_request_sections(const u8 *stream_data, usz len,
                                     const u8 **fs, usz *fs_len,
                                     quic_h3reqdrive_req *r)
{
    quic_stream_frame f;
    usz end = 0;
    if (!quic_frame_get_stream(stream_data, len, &f))
        return 0;
    if (!find_headers(f.data, (usz)f.length, fs, fs_len, &end))
        return 0;
    return find_body(f.data, (usz)f.length, end, r);
}
