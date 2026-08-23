#include "app/http3/request/h3resp/field_encode.h"

#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/literal.h"
#include "app/qpack/qpack/prefix.h"
#include "app/qpack/qpack/static_table.h"
#include "app/qpack/qpackenc/status_line.h"
#include "common/bytes/util/bytes.h"

/* Static table index of the first "content-type" name entry (RFC 9204 App.
 * A): used as a name-only reference regardless of which value it pairs. */
#define QPACK_CONTENT_TYPE_NAME_INDEX 44

/* Encode the Encoded Field Section Prefix at *off, carrying the Required
 * Insert Count a dynamic-table :status reference/insert demands (RFC 9204
 * 4.5.1) -- 0 when the caller's qenc has no dynamic table capacity (or the
 * caller passed none at all, see put_status_line's own doc). */
static usz resp_put_prefix(u64 required_insert_count, u8* out, usz cap) {
  qpack_prefix pfx = {required_insert_count, 0, 0};
  return qpack_prefix_encode(out, cap, &pfx);
}

/* A caller-passed qenc, or a throwaway zero-capacity state when the caller
 * has no connection-scoped encoder state (e.g. h3resp_encode_headers) --
 * qpackenc_status_line always resolves a zero-capacity state through its
 * static-or-literal path (RFC 9204 3.2's "no dynamic table" default),
 * byte-identical to this function's pre-dynamic-table behavior, and never
 * an insert. */
static qpackenc_state* qenc_or_fallback(
    qpackenc_state* qenc, qpackenc_state* tmp) {
  if (qenc) return qenc;
  qpackenc_init(tmp, 0);
  return tmp;
}

/* Append the :status field line via qpackenc_status_line, updating *r with
 * the full result (Required Insert Count for the Prefix, plus any pending
 * encoder-stream instruction the call generated -- r->insert_len == 0 if
 * none). */
static usz put_status_line(
    u16                     status,
    qpackenc_state*         qenc,
    u8*                     out,
    usz                     cap,
    qpackenc_status_result* r) {
  qpackenc_state tmp;
  qenc = qenc_or_fallback(qenc, &tmp);
  if (!qpackenc_status_line(status, qenc, r)) return 0;
  if (r->field_len > cap) return 0;
  bytes_memcpy(out, r->field, r->field_len);
  return r->field_len;
}

/* Append the content-type field line: Indexed when the value is in the
 * static table, else a Literal referencing the static content-type name. */
static usz put_content_type_line(const char* content_type, u8* out, usz cap) {
  qpack_nameref r   = {QPACK_CONTENT_TYPE_NAME_INDEX, 1, 0};
  usz           len = wired_cstr_len(content_type);
  i64           idx = qpack_static_find("content-type", content_type);
  if (idx >= 0)
    return qpack_indexed_encode(wired_mspan_of(out, cap), (u64)idx, 1);
  return qpack_literal_namref_encode(
      wired_mspan_of(out, cap), &r,
      wired_span_of((const u8*)content_type, len));
}

/* Append the content-type field line at *off when content_type is non-null;
 * a no-op (success) otherwise. */
static int append_content_type(
    const char* content_type, u8* out, usz cap, usz* off) {
  usz n;
  if (!content_type) return 1;
  n = put_content_type_line(content_type, out + *off, cap - *off);
  if (!n) return 0;
  *off += n;
  return 1;
}

/* 1 iff the Prefix (pre_len bytes) and the :status line (status_len bytes)
 * both fit in cap -- the combined guard put_prefix_and_status needs, split
 * out so its own CCN counts only one predicate call, not the "||" inside. */
static int prefix_and_status_fit(usz pre_len, usz status_len, usz cap) {
  return pre_len && pre_len + status_len <= cap;
}

/* Encode the prefix followed by the :status line into out, returning the
 * byte offset past both, or 0 if either lacks capacity. The Prefix must be
 * encoded AFTER the :status line since its Required Insert Count depends on
 * whether that line referenced/inserted into the dynamic table -- written
 * into a scratch buffer here and copied ahead of the :status bytes. */
static usz put_prefix_and_status(
    u16                     status,
    qpackenc_state*         qenc,
    u8*                     out,
    usz                     cap,
    qpackenc_status_result* r) {
  u8  status_buf[64];
  usz status_len =
      put_status_line(status, qenc, status_buf, sizeof status_buf, r);
  usz pre_len;
  if (!status_len) return 0;
  pre_len = resp_put_prefix(r->required_insert_count, out, cap);
  if (!prefix_and_status_fit(pre_len, status_len, cap)) return 0;
  bytes_memcpy(out + pre_len, status_buf, status_len);
  return pre_len + status_len;
}

/* Append one Literal Field Line With Literal Name (RFC 9204 4.5.6) at *off
 * when extra is non-null; a no-op (success) otherwise. */
static int append_extra_field(
    const qpack_field* extra, u8* out, usz cap, usz* off) {
  usz n;
  if (!extra) return 1;
  n = qpack_literal_name_encode(
      wired_mspan_of(out + *off, cap - *off), 0, extra);
  if (!n) return 0;
  *off += n;
  return 1;
}

/* Encode the prefix, the :status line and the optional content-type line
 * into out, returning the byte offset past them, or 0 on overflow. */
static usz put_status_and_ct(
    u16                     status,
    const char*             content_type,
    qpackenc_state*         qenc,
    u8*                     out,
    usz                     cap,
    qpackenc_status_result* r) {
  usz off = put_prefix_and_status(status, qenc, out, cap, r);
  if (!off) return 0;
  return append_content_type(content_type, out, cap, &off) ? off : 0;
}

/* RFC 9204 4.5. qenc == 0 behaves exactly as before this connection-scoped
 * encoder state existed (static-or-literal :status only, empty Prefix).
 * *insert_out (never null: caller-owned scratch) receives any pending
 * encoder-stream instruction the :status line generated -- insert_len == 0
 * always when qenc == 0. */
int h3resp_encode_headers_field_qenc(
    u16                     status,
    const char*             content_type,
    const qpack_field*      extra,
    qpackenc_state*         qenc,
    qpackenc_status_result* insert_out,
    wired_obuf*             out) {
  usz off = put_status_and_ct(
      status, content_type, qenc, out->p, out->cap, insert_out);
  if (!off) return 0;
  if (!append_extra_field(extra, out->p, out->cap, &off)) return 0;
  out->len = off;
  return 1;
}

/* RFC 9204 4.5 */
int h3resp_encode_headers_field(
    u16                status,
    const char*        content_type,
    const qpack_field* extra,
    wired_obuf*        out) {
  qpackenc_status_result unused;
  return h3resp_encode_headers_field_qenc(
      status, content_type, extra, 0, &unused, out);
}

/* RFC 9204 4.5 */
int h3resp_encode_headers(
    u16 status, const char* content_type, wired_obuf* out) {
  return h3resp_encode_headers_field(status, content_type, 0, out);
}
