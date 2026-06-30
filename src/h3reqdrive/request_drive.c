#include "h3reqdrive/request_drive.h"
#include "h3conn/request.h"
#include "h3reqenc/request_headers.h"
#include "h3/frame.h"
#include "h3/pseudoheader.h"
#include "frame/frame.h"
#include "qpack/fieldline.h"
#include "qpack/literal.h"
#include "qpack/prefix.h"
#include "qpack/static_table.h"

/* RFC 9114 4.1 / 4.3.1, RFC 9204 4.5 */
int quic_h3reqdrive_send_method(u64 stream_id, const u8 *method, usz m_len,
                                const u8 *path, usz p_len, const u8 *authority,
                                usz a_len, const u8 *body, usz body_len,
                                u8 *out, usz cap, usz *out_len)
{
    u8 fs[256];
    usz fs_len = 0;
    if (!quic_h3req_enc_method(method, m_len, path, p_len, authority, a_len, fs,
                               sizeof(fs), &fs_len))
        return 0;
    return quic_h3conn_send_request(stream_id, fs, fs_len, body, body_len, out,
                                    cap, out_len);
}

/* RFC 9114 4.1 / 4.3.1, RFC 9204 4.5 */
int quic_h3reqdrive_send_get(u64 stream_id, const u8 *path, usz p_len,
                             const u8 *authority, usz a_len,
                             u8 *out, usz cap, usz *out_len)
{
    static const u8 method[] = {'G', 'E', 'T'};
    return quic_h3reqdrive_send_method(stream_id, method, 3, path, p_len,
                                       authority, a_len, 0, 0, out, cap,
                                       out_len);
}

/* One recovered field line: name and value, each borrowed from the static
 * table or copied into the caller's scratch. */
typedef struct {
    const u8 *name;
    usz name_len;
    const u8 *value;
    usz value_len;
    usz scratch_used;  /* scratch octets this line occupies (0 if borrowed) */
} rline;

/* Length of a NUL-terminated static-table string. */
static usz cstr_len(const char *s)
{
    usz i = 0;
    while (s[i]) i++;
    return i;
}

/* Borrow the static entry's name/value into L (both NUL-terminated strings). */
static void borrow_static(const char *name, const char *value, rline *L)
{
    L->name = (const u8 *)name;
    L->name_len = cstr_len(name);
    L->value = (const u8 *)value;
    L->value_len = cstr_len(value);
    L->scratch_used = 0;
}

/* RFC 9204 4.5.2: an Indexed Field Line -> the static entry's name and value. */
static usz line_indexed(const u8 *fs, usz n, u8 *scr, usz scap, rline *L)
{
    u64 index = 0;
    int is_static = 0;
    const char *name = 0, *value = 0;
    usz c = quic_qpack_indexed_decode(fs, n, &index, &is_static);
    (void)scr; (void)scap;
    if (!c || !quic_qpack_static_get((usz)index, &name, &value))
        return 0;
    borrow_static(name, value, L);
    return c;
}

/* RFC 9204 4.5.4: a Literal With Name Reference -> static name, copied value. */
static usz line_namref(const u8 *fs, usz n, u8 *scr, usz scap, rline *L)
{
    u64 index = 0;
    int is_static = 0, never = 0;
    usz vlen = 0;
    const char *name = 0, *value = 0;
    usz c = quic_qpack_literal_namref_decode(fs, n, &index, &is_static, &never,
                                             scr, scap, &vlen);
    if (!c || !quic_qpack_static_get((usz)index, &name, &value))
        return 0;
    L->name = (const u8 *)name; L->name_len = cstr_len(name);
    L->value = scr;             L->value_len = vlen;
    L->scratch_used = vlen;
    return c;
}

/* RFC 9204 4.5.6: a Literal With Literal Name -> name in the first scratch
 * half, value in the second (disjoint, since both are written in one call). */
static usz line_litname(const u8 *fs, usz n, u8 *scr, usz scap, rline *L)
{
    int never = 0;
    usz half = scap / 2, nlen = 0, vlen = 0;
    usz c = quic_qpack_literal_name_decode(fs, n, &never, scr, half, &nlen,
                                           scr + half, scap - half, &vlen);
    if (!c)
        return 0;
    L->name = scr;         L->name_len = nlen;
    L->value = scr + half; L->value_len = vlen;
    L->scratch_used = half + vlen;
    return c;
}

/* RFC 9204 4.5: decode one field line of any of the three forms. */
static usz decode_line(const u8 *fs, usz n, u8 *scr, usz scap, rline *L)
{
    usz c = line_indexed(fs, n, scr, scap, L);
    if (c)
        return c;
    c = line_namref(fs, n, scr, scap, L);
    if (c)
        return c;
    return line_litname(fs, n, scr, scap, L);
}

/* A request pseudo-header kind has a (value, len) slot in quic_h3reqdrive_req. */
static int is_request_pseudo(quic_h3_ph_kind k)
{
    return k >= QUIC_H3_PH_METHOD && k <= QUIC_H3_PH_PATH;
}

/* Store one recovered line into r if it is a request pseudo-header; regular
 * fields and unknown pseudo-headers are ignored (RFC 9114 4.3.1). The slot
 * tables are indexed by kind, whose enum order matches the struct fields. */
static void classify_line(const rline *L, quic_h3reqdrive_req *r)
{
    const u8 **val[] = {0, &r->method, &r->scheme, &r->authority, &r->path};
    usz *len[] = {0, &r->method_len, &r->scheme_len, &r->authority_len,
                  &r->path_len};
    quic_h3_ph_kind k = quic_h3_ph_classify(L->name, L->name_len);
    if (!is_request_pseudo(k))
        return;
    *val[k] = L->value;
    *len[k] = L->value_len;
}

/* Decode one line at *off into r, advancing *off and the scratch cursor *used.
 * Returns 1 ok, 0 on a malformed line. */
static int step_line(const u8 *fs, usz n, u8 *scr, usz scap, usz *off,
                     usz *used, quic_h3reqdrive_req *r)
{
    rline L;
    usz c = decode_line(fs + *off, n - *off, scr + *used, scap - *used, &L);
    if (!c)
        return 0;
    classify_line(&L, r);
    *off += c;
    *used += L.scratch_used;
    return 1;
}

/* Walk field lines from off to n into r. Returns 1 ok, 0 on a malformed line. */
static int scan_lines(const u8 *fs, usz n, u8 *scr, usz scap, usz off,
                     quic_h3reqdrive_req *r)
{
    usz used = 0;
    while (off < n)
        if (!step_line(fs, n, scr, scap, &off, &used, r))
            return 0;
    return 1;
}

/* RFC 9114 4.3.1: walk every field line after the section prefix in any order
 * or count, recovering the request pseudo-headers into r by name. */
static int decode_lines(const u8 *fs, usz n, u8 *scr, usz scap,
                        quic_h3reqdrive_req *r)
{
    usz off = quic_qpack_prefix_decode(fs, n, &(quic_qpack_prefix){0});
    if (!off)
        return 0;
    return scan_lines(fs, n, scr, scap, off, r);
}

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

/* Read one DATA frame at the head of buf into r's body view. Returns 1 ok,
 * 0 if truncated or the frame is not a DATA frame. */
static int take_data(const u8 *buf, usz n, quic_h3reqdrive_req *r)
{
    u64 type = 0, plen = 0;
    if (!quic_h3_frame_get(buf, n, &type, &r->body, &plen) ||
        type != QUIC_H3_FRAME_DATA)
        return 0;
    r->body_len = (usz)plen;
    return 1;
}

/* RFC 9114 4.1: view the request body carried by the DATA frame following
 * HEADERS. No remaining bytes means a bodyless request (GET): leave the view
 * empty and succeed. A present-but-malformed remainder fails. The first DATA
 * frame is taken; a request split across multiple DATA frames is not joined
 * (curl/typical clients send one). */
static int find_body(const u8 *h3, usz n, usz off, quic_h3reqdrive_req *r)
{
    if (off >= n)
        return 1;
    return take_data(h3 + off, n - off, r);
}

/* RFC 9114 4.1: take the request STREAM frame, locate its HEADERS field
 * section tolerating leading unknown frames (RFC 9114 9), then view the
 * trailing DATA frame body. */
static int request_sections(const u8 *stream_data, usz len, const u8 **fs,
                            usz *fs_len, quic_h3reqdrive_req *r)
{
    quic_stream_frame f;
    usz end = 0;
    if (!quic_frame_get_stream(stream_data, len, &f))
        return 0;
    if (!find_headers(f.data, (usz)f.length, fs, fs_len, &end))
        return 0;
    return find_body(f.data, (usz)f.length, end, r);
}

/* RFC 9114 4.1, RFC 9204 4.5 */
int quic_h3reqdrive_recv_get(const u8 *stream_data, usz len,
                             u8 *scratch, usz scap, quic_h3reqdrive_req *r)
{
    const u8 *fs = 0;
    usz fs_len = 0;
    *r = (quic_h3reqdrive_req){0};
    if (!request_sections(stream_data, len, &fs, &fs_len, r))
        return 0;
    return decode_lines(fs, fs_len, scratch, scap, r);
}
