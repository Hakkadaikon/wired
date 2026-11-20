#include "app/http3/core/h3conn/response.h"

#include "app/http3/request/h3req/respparse.h"
#include "app/http3/request/h3resp/resp_build.h"
#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/literal.h"
#include "app/qpack/qpack/prefix.h"
#include "app/qpack/qpack/static_table.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/stream/data/appdata/stream_send.h"

/* RFC 9114 4.1 / RFC 9000 19.8 */
int h3conn_send_response(
    u64 stream_id, const h3conn_resp* resp, wired_obuf* out) {
  u8         h3[1500];
  wired_obuf h3ob = obuf_of(h3, sizeof(h3));
  if (!h3resp_build(resp->status, resp->content_type, resp->body, &h3ob)) {
    return 0;
  }
  {
    stream_frame f = {stream_id, 0, h3ob.len, h3, 1};
    if (!appdata_stream_frame(&f, out)) {
      return 0;
    }
    return 1;
  }
}

/* RFC 9110 15: three decimal ASCII digits to a status code. */
static u16 digits_to_status(const u8* d) {
  return (u16)((d[0] - '0') * 100 + (d[1] - '0') * 10 + (d[2] - '0'));
}

static int status_digit(u8 c) { return c >= '0' && c <= '9'; }

/* RFC 9110 15: exactly three decimal ASCII digits. */
static int status_digits3(const u8* d) {
  return status_digit(d[0]) && status_digit(d[1]) && status_digit(d[2]);
}

/* RFC 9114 4.3.2: the response pseudo-header name is exactly ":status". */
static int status_name_ok(const char* name) {
  static const char want[] = ":status";
  for (usz i = 0; i < sizeof want; i++) {
    if (name[i] != want[i]) {
      return 0;
    }
  }
  return 1;
}

/* The static entry's value is exactly three digits (checked before any
 * conversion reads it -- :authority's value, say, is a single NUL). */
static int status_value3(const char* v) {
  return status_digits3((const u8*)v) && v[3] == 0;
}

/* RFC 9114 4.3.2 / RFC 9110 15: a static reference naming :status with a
 * three-digit value; anything else is a malformed response. */
static int status_entry_ok(int is_static, const char* name, const char* v) {
  return is_static && status_name_ok(name) && status_value3(v);
}

/* Decode an indexed field line into a static-table entry. Returns 1 ok. */
static int indexed_entry(
    const u8* buf, usz n, int* is_static, const char** nm, const char** v) {
  u64 index = 0;
  return qpack_indexed_decode(wired_span_of(buf, n), &index, is_static) &&
         qpack_static_get((usz)index, nm, v);
}

/* RFC 9204 4.5.2: Indexed :status -> look up the static entry's value. */
static int status_from_indexed(const u8* buf, usz n, u16* status) {
  int         is_static = 0;
  const char* name      = 0;
  const char* value     = 0;
  if (!indexed_entry(buf, n, &is_static, &name, &value)) {
    return 0;
  }
  if (!status_entry_ok(is_static, name, value)) {
    return 0;
  }
  *status = digits_to_status((const u8*)value);
  return 1;
}

/* RFC 9114 4.3.2: the literal's name reference is the static :status
 * entry -- a dynamic one has no table on this response path. */
static int literal_names_status(const qpack_nameref* r) {
  const char* name  = 0;
  const char* value = 0;
  return r->is_static && qpack_static_get((usz)r->index, &name, &value) &&
         status_name_ok(name);
}

/* RFC 9114 4.3.2 / RFC 9110 15: :status name and a three-digit value. */
static int literal_status_ok(const qpack_nameref* r, const wired_obuf* vb) {
  return literal_names_status(r) && vb->len == 3 && status_digits3(vb->p);
}

/* RFC 9204 4.5.4: Literal :status with name reference -> its 3-octet value. */
static int status_from_literal(const u8* buf, usz n, u16* status) {
  qpack_nameref r = {0, 0, 0};
  u8            val[8];
  wired_obuf    vb = obuf_of(val, sizeof(val));
  if (!qpack_literal_namref_decode(wired_span_of(buf, n), &r, &vb)) {
    return 0;
  }
  if (!literal_status_ok(&r, &vb)) {
    return 0;
  }
  *status = digits_to_status(val);
  return 1;
}

/* RFC 9204 4.5: decode the single :status field line after the section prefix.
 */
static int decode_status(const u8* fs, usz n, u16* status) {
  usz off = qpack_prefix_decode(fs, n, &(qpack_prefix){0});
  if (!off) {
    return 0;
  }
  if (status_from_indexed(fs + off, n - off, status)) {
    return 1;
  }
  return status_from_literal(fs + off, n - off, status);
}

/* RFC 9114 4.1 / RFC 9000 19.8 */
int h3conn_recv_response(wired_span stream_data, h3conn_resp* resp) {
  stream_frame f;
  h3req_resp   rp = {0};
  if (!frame_get_stream(stream_data.p, stream_data.n, &f)) {
    return 0;
  }
  if (!h3req_resp_parse(wired_span_of(f.data, (usz)f.length), &rp)) {
    return 0;
  }
  resp->body = rp.body;
  return decode_status(rp.headers.p, rp.headers.n, &resp->status);
}
