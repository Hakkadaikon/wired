#include "app/http3/request/h3reqdrive/request_drive.h"

#include "app/http3/core/h3/pseudoheader.h"
#include "app/http3/core/h3conn/request.h"
#include "app/http3/request/h3reqdrive/request_parse.h"
#include "app/http3/request/h3reqenc/request_headers.h"
#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/literal.h"
#include "app/qpack/qpack/prefix.h"
#include "app/qpack/qpack/static_table.h"

/* RFC 9114 4.1 / 4.3.1, RFC 9204 4.5 */
int quic_h3reqdrive_send_method(
    u64 stream_id, const quic_h3reqdrive_send_in *in, quic_obuf *out) {
  u8        fs[256];
  quic_obuf fsb = quic_obuf_of(fs, sizeof(fs));
  quic_h3req_headers_in hin = {in->path, in->authority};
  quic_h3conn_req_in    rin;
  if (!quic_h3req_enc_method(in->method, &hin, &fsb)) return 0;
  rin = (quic_h3conn_req_in){quic_span_of(fs, fsb.len), in->body};
  return quic_h3conn_send_request(stream_id, &rin, out);
}

/* RFC 9114 4.1 / 4.3.1, RFC 9204 4.5 */
int quic_h3reqdrive_send_get(
    u64 stream_id, const quic_h3reqdrive_get_in *in, quic_obuf *out) {
  static const u8         method[] = {'G', 'E', 'T'};
  quic_h3reqdrive_send_in sin      = {
      quic_span_of(method, 3), in->path, in->authority, quic_span_of(0, 0)};
  return quic_h3reqdrive_send_method(stream_id, &sin, out);
}

/* One recovered field line: name and value, each borrowed from the static
 * table or copied into the caller's scratch. */
typedef struct {
  const u8 *name;
  usz       name_len;
  const u8 *value;
  usz       value_len;
  usz scratch_used; /* scratch octets this line occupies (0 if borrowed) */
} rline;

/* Length of a NUL-terminated static-table string. */
static usz cstr_len(const char *s) {
  usz i = 0;
  while (s[i]) i++;
  return i;
}

/* Borrow the static entry's name/value into L (both NUL-terminated strings). */
static void borrow_static(const char *name, const char *value, rline *L) {
  L->name         = (const u8 *)name;
  L->name_len     = cstr_len(name);
  L->value        = (const u8 *)value;
  L->value_len    = cstr_len(value);
  L->scratch_used = 0;
}

/* RFC 9204 4.5.2: an Indexed Field Line -> the static entry's name and value.
 */
static usz line_indexed(quic_span fs, quic_mspan scr, rline *L) {
  u64         index     = 0;
  int         is_static = 0;
  const char *name = 0, *value = 0;
  usz c = quic_qpack_indexed_decode(fs, &index, &is_static);
  (void)scr;
  if (!c || !quic_qpack_static_get((usz)index, &name, &value)) return 0;
  borrow_static(name, value, L);
  return c;
}

/* RFC 9204 4.5.4: a Literal With Name Reference -> static name, copied value.
 */
static usz line_namref(quic_span fs, quic_mspan scr, rline *L) {
  quic_qpack_nameref r    = {0, 0, 0};
  quic_obuf          vb   = quic_obuf_of(scr.p, scr.n);
  const char        *name = 0, *value = 0;
  usz c = quic_qpack_literal_namref_decode(fs, &r, &vb);
  if (!c || !quic_qpack_static_get((usz)r.index, &name, &value)) return 0;
  L->name         = (const u8 *)name;
  L->name_len     = cstr_len(name);
  L->value        = scr.p;
  L->value_len    = vb.len;
  L->scratch_used = vb.len;
  return c;
}

/* RFC 9204 4.5.6: a Literal With Literal Name -> name in the first scratch
 * half, value in the second (disjoint, since both are written in one call). */
static usz line_litname(quic_span fs, quic_mspan scr, rline *L) {
  int                 never = 0;
  usz                 half  = scr.n / 2;
  quic_qpack_fieldbuf fb    = {
      quic_obuf_of(scr.p, half), quic_obuf_of(scr.p + half, scr.n - half)};
  usz c = quic_qpack_literal_name_decode(fs, &never, &fb);
  if (!c) return 0;
  L->name         = scr.p;
  L->name_len     = fb.name.len;
  L->value        = scr.p + half;
  L->value_len    = fb.value.len;
  L->scratch_used = half + fb.value.len;
  return c;
}

/* RFC 9204 4.5: decode one field line of any of the three forms. */
static usz decode_line(quic_span fs, quic_mspan scr, rline *L) {
  usz c = line_indexed(fs, scr, L);
  if (c) return c;
  c = line_namref(fs, scr, L);
  if (c) return c;
  return line_litname(fs, scr, L);
}

/* A request pseudo-header kind has a (value, len) slot in quic_h3reqdrive_req.
 */
static int is_request_pseudo(quic_h3_ph_kind k) {
  return k >= QUIC_H3_PH_METHOD && k <= QUIC_H3_PH_PATH;
}

/* Store one recovered line into r if it is a request pseudo-header; regular
 * fields and unknown pseudo-headers are ignored (RFC 9114 4.3.1). The slot
 * tables are indexed by kind, whose enum order matches the struct fields. */
static void classify_line(const rline *L, quic_h3reqdrive_req *r) {
  const u8 **val[] = {0, &r->method, &r->scheme, &r->authority, &r->path};
  usz       *len[] = {
      0, &r->method_len, &r->scheme_len, &r->authority_len, &r->path_len};
  quic_h3_ph_kind k = quic_h3_ph_classify(L->name, L->name_len);
  if (!is_request_pseudo(k)) return;
  *val[k] = L->value;
  *len[k] = L->value_len;
}

/* Cursor state shared by the field-line walkers below: the field section and
 * scratch buffer being walked, an offset into the section and how much
 * scratch has been consumed so far. */
typedef struct {
  quic_span  fs;
  quic_mspan scr;
  usz        off;
  usz        used;
} rd_cursor;

/* Decode one line at cur->off into r, advancing cur. Returns 1 ok, 0 on a
 * malformed line. */
static int step_line(rd_cursor *cur, quic_h3reqdrive_req *r) {
  rline L;
  usz   c = decode_line(
      quic_span_of(cur->fs.p + cur->off, cur->fs.n - cur->off),
      quic_mspan_of(cur->scr.p + cur->used, cur->scr.n - cur->used), &L);
  if (!c) return 0;
  classify_line(&L, r);
  cur->off += c;
  cur->used += L.scratch_used;
  return 1;
}

/* Walk field lines from cur->off to cur->fs.n into r. Returns 1 ok, 0 on a
 * malformed line. */
static int scan_lines(rd_cursor *cur, quic_h3reqdrive_req *r) {
  while (cur->off < cur->fs.n)
    if (!step_line(cur, r)) return 0;
  return 1;
}

/* RFC 9114 4.3.1: walk every field line after the section prefix in any order
 * or count, recovering the request pseudo-headers into r by name. */
static int decode_lines(quic_span fs, quic_mspan scr, quic_h3reqdrive_req *r) {
  rd_cursor cur = {fs, scr, 0, 0};
  cur.off = quic_qpack_prefix_decode(fs.p, fs.n, &(quic_qpack_prefix){0});
  if (!cur.off) return 0;
  return scan_lines(&cur, r);
}

/* RFC 9114 4.1, RFC 9204 4.5 */
int quic_h3reqdrive_recv_get(
    quic_span stream_data, quic_mspan scratch, quic_h3reqdrive_req *r) {
  quic_span fs = quic_span_of(0, 0);
  *r           = (quic_h3reqdrive_req){0};
  if (!quic_h3reqdrive_request_sections(stream_data, &fs, r)) return 0;
  if (!decode_lines(fs, scratch, r)) return 0;
  return 1;
}
