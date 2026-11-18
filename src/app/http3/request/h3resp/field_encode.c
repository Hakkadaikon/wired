#include "app/http3/request/h3resp/field_encode.h"

#include "app/qpack/qpack/static_table.h"
#include "common/bytes/util/bytes.h"

/* RFC 9204 App. A: the first ":status" and "content-type" name entries,
 * referenced by a literal whose value has no static entry. */
#define H3RESP_STATUS_NAME_INDEX 24
#define H3RESP_CONTENT_TYPE_NAME_INDEX 44
/* :status, content-type, and the extra fields: srvrun adds at most
 * WIRED_HTTP_MAX_FIELDS (8) app fields plus its own few (srvrun_hdrs). */
#define H3RESP_LINES_MAX 18

/* One response's field lines, with the :status digits they view. */
typedef struct {
  qpackenc_line l[H3RESP_LINES_MAX];
  usz           n;
  u8            digits[4];
} h3resp_lines;

/* RFC 9110 15: HTTP status codes are always exactly three digits. */
static void h3resp_status_line(h3resp_lines* s, u16 status) {
  s->digits[0] = (u8)('0' + (status / 100) % 10);
  s->digits[1] = (u8)('0' + (status / 10) % 10);
  s->digits[2] = (u8)('0' + status % 10);
  s->digits[3] = 0;
  s->l[0]      = (qpackenc_line){
      {wired_span_of((const u8*)":status", 7), wired_span_of(s->digits, 3)},
      qpack_static_find(":status", (const char*)s->digits),
      H3RESP_STATUS_NAME_INDEX,
      1};
  s->n = 1;
}

/* The content-type line when content_type is non-null. */
static void h3resp_ct_line(h3resp_lines* s, const char* content_type) {
  if (!content_type) {
    return;
  }
  s->l[s->n++] = (qpackenc_line){
      {wired_span_of((const u8*)"content-type", 12),
       wired_span_of((const u8*)content_type, wired_cstr_len(content_type))},
      qpack_static_find("content-type", content_type),
      H3RESP_CONTENT_TYPE_NAME_INDEX,
      1};
}

/* One line per extra field; 0 when they do not all fit. RFC 9114 10.6:
 * an application's field can carry a secret or text a request made it
 * echo, so it is never inserted -- the table only ever holds :status and
 * the content-type, both values the server chose (content_type is a static
 * string by contract, wired_http_exchange). It still goes out as a Literal
 * Field Line With Literal Name. */
static int h3resp_extra_lines(
    h3resp_lines* s, const qpack_field* extra, usz n) {
  if (n > H3RESP_LINES_MAX - s->n) {
    return 0;
  }
  for (usz i = 0; i < n; i++) {
    s->l[s->n++] = (qpackenc_line){extra[i], -1, -1, 0};
  }
  return 1;
}

/* A caller-passed qenc, or a zero-capacity state when the caller has no
 * connection-scoped encoder (h3resp_encode_headers): static-or-literal
 * only, never an insert (RFC 9204 3.2's "no dynamic table" default). */
static const qpackenc_state* qenc_or_fallback(
    const qpackenc_state* qenc, qpackenc_state* tmp) {
  if (qenc) {
    return qenc;
  }
  qpackenc_init(tmp, 0);
  return tmp;
}

/* RFC 9204 4.5. *insert_out receives the section's Required Insert Count
 * and its pending encoder-stream instruction (none when qenc == 0). */
int h3resp_encode_headers_fields_qenc(
    u16                      status,
    const char*              content_type,
    const qpack_field*       extra,
    usz                      n_extra,
    qpackenc_state*          qenc,
    qpackenc_section_result* insert_out,
    wired_obuf*              out) {
  h3resp_lines   s;
  qpackenc_state tmp;
  h3resp_status_line(&s, status);
  h3resp_ct_line(&s, content_type);
  if (!h3resp_extra_lines(&s, extra, n_extra)) {
    return 0;
  }
  return qpackenc_section_encode(
      qenc_or_fallback(qenc, &tmp), s.l, s.n, out, insert_out);
}

/* RFC 9204 4.5: the single-extra form (extra == 0 adds none). */
int h3resp_encode_headers_field_qenc(
    u16                      status,
    const char*              content_type,
    const qpack_field*       extra,
    qpackenc_state*          qenc,
    qpackenc_section_result* insert_out,
    wired_obuf*              out) {
  return h3resp_encode_headers_fields_qenc(
      status, content_type, extra, extra != 0, qenc, insert_out, out);
}

/* RFC 9204 4.5 */
int h3resp_encode_headers_field(
    u16                status,
    const char*        content_type,
    const qpack_field* extra,
    wired_obuf*        out) {
  qpackenc_section_result unused;
  return h3resp_encode_headers_field_qenc(
      status, content_type, extra, 0, &unused, out);
}

/* RFC 9204 4.5 */
int h3resp_encode_headers(
    u16 status, const char* content_type, wired_obuf* out) {
  return h3resp_encode_headers_field(status, content_type, 0, out);
}
