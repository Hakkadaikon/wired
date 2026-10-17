#include "app/http3/request/h3reqdrive/request_drive_impl.h"

static int line_is_indexed(u8 lead);
static int borrow_static(const qpack_field* f, rline* L);
static int indexed_keep(
    const qpack_field* f, u8 lead, wired_mspan scr, rline* L);

/* RFC 9114 4.1 / 4.3.1, RFC 9204 4.5 */
int wired_h3reqdrive_send_method(
    u64 stream_id, const wired_h3reqdrive_send_in* in, wired_obuf* out) {
  u8               fs[256];
  wired_obuf       fsb = obuf_of(fs, sizeof(fs));
  h3req_headers_in hin = {in->path, in->authority};
  h3conn_req_in    rin;
  if (!h3req_enc_method(in->method, &hin, &fsb)) return 0;
  rin = (h3conn_req_in){wired_span_of(fs, fsb.len), in->body};
  return h3conn_send_request(stream_id, &rin, out);
}

/* RFC 9114 4.1 / 4.3.1, RFC 9204 4.5 */
int wired_h3reqdrive_send_get(
    u64 stream_id, const wired_h3reqdrive_get_in* in, wired_obuf* out) {
  static const u8          method[] = {'G', 'E', 'T'};
  wired_h3reqdrive_send_in sin      = {
      wired_span_of(method, 3), in->path, in->authority, wired_span_of(0, 0)};
  return wired_h3reqdrive_send_method(stream_id, &sin, out);
}

/* Length of a NUL-terminated static-table string. */
usz h3reqdrive_cstr_len(const char* s) {
  usz i = 0;
  while (s[i]) i++;
  return i;
}

/* RFC 9204 4.5.2 / 4.5.3: an Indexed Field Line or Indexed Field Line with
 * Post-Base Index -> the referenced entry's name and value, dynamic-table
 * (T=0, or the post-Base form, always dynamic) references resolved against
 * dyn->table when set; a caller with no dynamic table (dyn->table == 0, e.g.
 * no encoder stream has been seen yet) simply cannot resolve one, matching
 * this decoder's prior static-table-only behavior. */
/* A literal line: name as resolved, value copied into scr (vlen bytes). */
void h3reqdrive_literal_line(
    rline* L, wired_span name, wired_mspan scr, usz vlen) {
  L->name         = name.p;
  L->name_len     = name.n;
  L->value        = scr.p;
  L->value_len    = vlen;
  L->scratch_used = vlen;
}

/* RFC 9204 4.5.2 / 4.5.3: an Indexed Field Line ('1') or one with a
 * Post-Base Index ('0001'). */
static int line_is_indexed(u8 lead) {
  return (lead & 0x80) || (lead & 0xf0) == 0x10;
}

/* Borrow a static-table entry's name/value views into L (RFC 9204 3.1). */
static int borrow_static(const qpack_field* f, rline* L) {
  L->name         = f->name.p;
  L->name_len     = f->name.n;
  L->value        = f->value.p;
  L->value_len    = f->value.n;
  L->scratch_used = 0;
  return 1;
}

/* Keep an indexed line's entry: a static one as a view (it never changes),
 * a dynamic one's value copied into scr, never kept as a view -- a request
 * can outlive the step that acknowledged its section (a CONNECT held for
 * the peer's SETTINGS), and the peer may then evict the entry and overwrite
 * its bytes (RFC 9204 2.2.2 / 3.2). The name is only classified during this
 * decode. 0 if the value does not fit scr. */
static int indexed_keep(
    const qpack_field* f, u8 lead, wired_mspan scr, rline* L) {
  if ((lead & LINE_INDEXED_STATIC) == LINE_INDEXED_STATIC)
    return borrow_static(f, L);
  if (f->value.n > scr.n) return 0;
  bytes_memcpy(scr.p, f->value.p, f->value.n);
  h3reqdrive_literal_line(L, f->name, scr, f->value.n);
  return 1;
}

usz h3reqdrive_line_indexed(
    wired_span fs, wired_mspan scr, const qdyn_src* dyn, rline* L) {
  qpack_field f;
  usz         consumed;
  qdyn_src    src = {dyn->table, dyn->base, fs, dyn->ric};
  if (!qdyn_decode_field(&src, &f, &consumed)) {
    L->ref_bad = line_is_indexed(fs.p[0]);
    return 0;
  }
  return indexed_keep(&f, fs.p[0], scr, L) ? consumed : 0;
}
