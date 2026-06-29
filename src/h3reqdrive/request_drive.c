#include "h3reqdrive/request_drive.h"
#include "h3conn/request.h"
#include "h3reqenc/request_headers.h"
#include "h3req/respparse.h"
#include "frame/frame.h"
#include "qpack/fieldline.h"
#include "qpack/literal.h"
#include "qpack/prefix.h"
#include "qpack/static_table.h"

/* RFC 9114 4.1 / 4.3.1, RFC 9204 4.5 */
int quic_h3reqdrive_send_get(u64 stream_id, const u8 *path, usz p_len,
                             const u8 *authority, usz a_len,
                             u8 *out, usz cap, usz *out_len)
{
    u8 fs[256];
    usz fs_len = 0;
    if (!quic_h3req_enc_get(path, p_len, authority, a_len, fs, sizeof(fs),
                            &fs_len))
        return 0;
    return quic_h3conn_send_request(stream_id, fs, fs_len, 0, 0, out, cap,
                                    out_len);
}

/* One recovered field line: borrowed (or scratch-copied) name and value. */
typedef struct {
    const u8 *value;
    usz value_len;
} rline;

/* Length of a NUL-terminated static-table value. */
static usz cstr_len(const char *s)
{
    usz i = 0;
    while (s[i]) i++;
    return i;
}

/* Resolve an indexed field line at fs to the static entry's value. */
static const char *indexed_value(const u8 *fs, usz n, usz *consumed)
{
    u64 index = 0;
    int is_static = 0;
    const char *name = 0, *value = 0;
    *consumed = quic_qpack_indexed_decode(fs, n, &index, &is_static);
    if (!*consumed || !quic_qpack_static_get((usz)index, &name, &value))
        return 0;
    return value;
}

/* RFC 9204 4.5.2: an Indexed Field Line -> the static entry's value. */
static usz line_indexed(const u8 *fs, usz n, u8 *scr, usz scap, rline *L)
{
    usz c = 0;
    const char *value = indexed_value(fs, n, &c);
    (void)scr; (void)scap;
    if (!value)
        return 0;
    L->value = (const u8 *)value;
    L->value_len = cstr_len(value);
    return c;
}

/* RFC 9204 4.5.4: a Literal With Name Reference -> its copied value. */
static usz line_literal(const u8 *fs, usz n, u8 *scr, usz scap, rline *L)
{
    u64 index = 0;
    int is_static = 0, never = 0;
    usz vlen = 0;
    usz c = quic_qpack_literal_namref_decode(fs, n, &index, &is_static, &never,
                                             scr, scap, &vlen);
    if (!c)
        return 0;
    L->value = scr;
    L->value_len = vlen;
    return c;
}

/* RFC 9204 4.5: decode one field line, indexed or literal-namref. */
static usz decode_line(const u8 *fs, usz n, u8 *scr, usz scap, rline *L)
{
    usz c = line_indexed(fs, n, scr, scap, L);
    if (c)
        return c;
    return line_literal(fs, n, scr, scap, L);
}

/* Decode one line into out[i], advancing *off and *used. Returns 1 ok, 0 on
 * a malformed line. */
static int step_line(const u8 *fs, usz n, u8 *scr, usz scap, usz *off,
                     usz *used, rline *out)
{
    usz c = decode_line(fs + *off, n - *off, scr + *used, scap - *used, out);
    if (!c)
        return 0;
    *off += c;
    *used += out->value_len;
    return 1;
}

/* Decode four field lines starting at *off into out[0..3]. */
static int step_four(const u8 *fs, usz n, u8 *scr, usz scap, usz off,
                     rline out[4])
{
    usz used = 0;
    for (usz i = 0; i < 4; i++)
        if (!step_line(fs, n, scr, scap, &off, &used, &out[i]))
            return 0;
    return 1;
}

/* RFC 9114 4.3.1: decode the four request field lines in their fixed order
 * :method, :scheme, :authority, :path after the section prefix. */
static int decode_lines(const u8 *fs, usz n, u8 *scr, usz scap, rline out[4])
{
    usz off = quic_qpack_prefix_decode(fs, n, &(quic_qpack_prefix){0});
    if (!off)
        return 0;
    return step_four(fs, n, scr, scap, off, out);
}

/* RFC 9114 4.1: split a request STREAM frame into its HEADERS field section. */
static int request_field_section(const u8 *stream_data, usz len,
                                 const u8 **fs, usz *fs_len)
{
    quic_stream_frame f;
    const u8 *body = 0;
    usz body_len = 0;
    if (!quic_frame_get_stream(stream_data, len, &f))
        return 0;
    return quic_h3req_resp_parse(f.data, (usz)f.length, fs, fs_len, &body,
                                 &body_len);
}

/* RFC 9114 4.1, RFC 9204 4.5 */
int quic_h3reqdrive_recv_get(const u8 *stream_data, usz len,
                             u8 *scratch, usz scap, quic_h3reqdrive_req *r)
{
    const u8 *fs = 0;
    usz fs_len = 0;
    rline L[4];
    if (!request_field_section(stream_data, len, &fs, &fs_len))
        return 0;
    if (!decode_lines(fs, fs_len, scratch, scap, L))
        return 0;
    r->method = L[0].value;       r->method_len = L[0].value_len;
    r->scheme = L[1].value;       r->scheme_len = L[1].value_len;
    r->authority = L[2].value;    r->authority_len = L[2].value_len;
    r->path = L[3].value;         r->path_len = L[3].value_len;
    return 1;
}
