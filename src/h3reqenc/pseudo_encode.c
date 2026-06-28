#include "h3reqenc/pseudo_encode.h"
#include "qpack/prefix.h"
#include "qpack/fieldline.h"
#include "qpack/literal.h"
#include "qpack/static_table.h"

/* RFC 9204 Appendix A: static index of the first entry for each request
 * pseudo-header name, used as the Name Reference when the value is not in the
 * static table. */
#define QPACK_AUTHORITY_NAME_INDEX 0
#define QPACK_PATH_NAME_INDEX 1
#define QPACK_METHOD_NAME_INDEX 15
#define QPACK_SCHEME_NAME_INDEX 22

/* Longest static pseudo-header value (":method: OPTIONS") fits; values beyond
 * this are never in the static table and go out as a name reference. */
#define VALBUF_CAP 16

typedef struct {
    const u8 *val;
    usz vlen;
    const char *name;
    u64 name_idx;
} pseudo_field;

/* Copy val (vlen octets) into a NUL-terminated C string. Returns 1 ok, 0 if it
 * does not fit in buf of VALBUF_CAP octets (terminator included). */
static int val_cstr(const u8 *val, usz vlen, char *buf)
{
    if (vlen >= VALBUF_CAP) return 0;
    for (usz i = 0; i < vlen; i++) buf[i] = (char)val[i];
    buf[vlen] = 0;
    return 1;
}

/* RFC 9204 4.5.2. Static-table index of (name, val) if both are short enough to
 * compare and present, else -1. */
static i64 static_index(const pseudo_field *f, char *buf)
{
    if (!val_cstr(f->val, f->vlen, buf)) return -1;
    return quic_qpack_static_find(f->name, buf);
}

/* Encode one pseudo-header field line: Indexed when (name, value) is in the
 * static table, else a Literal With Name Reference. Returns bytes written or 0. */
static usz put_pseudo(const pseudo_field *f, u8 *out, usz cap)
{
    char buf[VALBUF_CAP];
    i64 idx = static_index(f, buf);
    if (idx >= 0) return quic_qpack_indexed_encode(out, cap, (u64)idx, 1);
    return quic_qpack_literal_namref_encode(out, cap, f->name_idx, 1, 0, f->val,
                                            f->vlen);
}

/* Encode the empty Encoded Field Section Prefix at out. */
static usz put_section_prefix(u8 *out, usz cap)
{
    quic_qpack_prefix pfx = {0, 0, 0};
    return quic_qpack_prefix_encode(out, cap, &pfx);
}

/* Append all four field lines from fields[0..3] after the prefix. Returns the
 * total length or 0 on overflow. */
static usz put_fields(const pseudo_field *fields, u8 *out, usz cap, usz off)
{
    for (usz i = 0; i < 4; i++) {
        usz n = put_pseudo(&fields[i], out + off, cap - off);
        if (!n) return 0;
        off += n;
    }
    return off;
}

/* RFC 9204 4.5 / RFC 9114 4.3.1 */
int quic_h3req_enc_pseudo(const u8 *method, usz m_len, const u8 *path,
                          usz p_len, const u8 *scheme, usz s_len,
                          const u8 *authority, usz a_len, u8 *out, usz cap,
                          usz *out_len)
{
    pseudo_field fields[4] = {
        {method, m_len, ":method", QPACK_METHOD_NAME_INDEX},
        {scheme, s_len, ":scheme", QPACK_SCHEME_NAME_INDEX},
        {authority, a_len, ":authority", QPACK_AUTHORITY_NAME_INDEX},
        {path, p_len, ":path", QPACK_PATH_NAME_INDEX},
    };
    usz off = put_section_prefix(out, cap);
    usz total;
    if (!off) return 0;
    total = put_fields(fields, out, cap, off);
    if (!total) return 0;
    *out_len = total;
    return 1;
}
