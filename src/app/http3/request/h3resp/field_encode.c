#include "app/http3/request/h3resp/field_encode.h"

#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/literal.h"
#include "app/qpack/qpack/prefix.h"
#include "app/qpack/qpack/static_table.h"
#include "common/bytes/util/bytes.h"

/* Static table index of the first ":status" name entry (RFC 9204 App. A). */
#define QPACK_STATUS_NAME_INDEX 24

/* Static table index of the first "content-type" name entry (RFC 9204 App.
 * A): used as a name-only reference regardless of which value it pairs. */
#define QPACK_CONTENT_TYPE_NAME_INDEX 44

/* Render a 3-digit HTTP status into dst[0..2] as decimal ASCII and NUL-
 * terminate at dst[3]. HTTP status codes are exactly three digits
 * (RFC 9110 15). */
static void status_digits(u16 status, u8 *dst) {
  dst[0] = (u8)('0' + (status / 100) % 10);
  dst[1] = (u8)('0' + (status / 10) % 10);
  dst[2] = (u8)('0' + status % 10);
  dst[3] = 0;
}

/* Encode the empty Encoded Field Section Prefix at *off. */
static usz resp_put_prefix(u8 *out, usz cap) {
  quic_qpack_prefix pfx = {0, 0, 0};
  return quic_qpack_prefix_encode(out, cap, &pfx);
}

/* Append the :status field line: Indexed when the value is in the static
 * table, else a Literal referencing the static :status name. */
static usz put_status_line(u16 status, u8 *out, usz cap) {
  u8                 digits[4];
  i64                idx;
  quic_qpack_nameref r = {QPACK_STATUS_NAME_INDEX, 1, 0};
  status_digits(status, digits);
  idx = quic_qpack_static_find(":status", (const char *)digits);
  if (idx >= 0)
    return quic_qpack_indexed_encode(quic_mspan_of(out, cap), (u64)idx, 1);
  return quic_qpack_literal_namref_encode(
      quic_mspan_of(out, cap), &r, quic_span_of(digits, 3));
}

/* Append the content-type field line: Indexed when the value is in the
 * static table, else a Literal referencing the static content-type name. */
static usz put_content_type_line(const char *content_type, u8 *out, usz cap) {
  quic_qpack_nameref r = {QPACK_CONTENT_TYPE_NAME_INDEX, 1, 0};
  usz                len = quic_cstr_len(content_type);
  i64                idx = quic_qpack_static_find("content-type", content_type);
  if (idx >= 0)
    return quic_qpack_indexed_encode(quic_mspan_of(out, cap), (u64)idx, 1);
  return quic_qpack_literal_namref_encode(
      quic_mspan_of(out, cap), &r, quic_span_of((const u8 *)content_type, len));
}

/* Append the content-type field line at *off when content_type is non-null;
 * a no-op (success) otherwise. */
static int append_content_type(
    const char *content_type, u8 *out, usz cap, usz *off) {
  usz n;
  if (!content_type) return 1;
  n = put_content_type_line(content_type, out + *off, cap - *off);
  if (!n) return 0;
  *off += n;
  return 1;
}

/* Encode the prefix followed by the :status line into out, returning the
 * byte offset past both, or 0 if either lacks capacity. */
static usz put_prefix_and_status(u16 status, u8 *out, usz cap) {
  usz off = resp_put_prefix(out, cap);
  usz n;
  if (!off) return 0;
  n = put_status_line(status, out + off, cap - off);
  return n ? off + n : 0;
}

/* RFC 9204 4.5 */
int quic_h3resp_encode_headers(
    u16 status, const char *content_type, quic_obuf *out) {
  usz off = put_prefix_and_status(status, out->p, out->cap);
  if (!off) return 0;
  if (!append_content_type(content_type, out->p, out->cap, &off)) return 0;
  out->len = off;
  return 1;
}
