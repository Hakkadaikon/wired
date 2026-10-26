#include "app/http3/core/h3/contentlen.h"
#include "app/http3/request/h3reqdrive/request_drive_impl.h"
#include "transport/packet/frame/frame/frame.h"

static int rc_digit_step(u64* v, u8 c);
static int rc_ph_shape_ok(const h3_ph_set* p, const wired_h3reqdrive_req* r);
static int rc_asterisk_ok(const wired_h3reqdrive_req* r);
static int rc_path_ok(const wired_h3reqdrive_req* r);
static int rc_target_ok(const wired_h3reqdrive_req* r);
static int rc_cl_take(wired_h3reqdrive_req* r);
static int rc_whole(wired_span stream_data);
static int rc_cl_applies(wired_span stream_data, const wired_h3reqdrive_req* r);
static int rc_cl_ok(wired_span stream_data, const wired_h3reqdrive_req* r);

/* One more decimal digit c onto *v; 0 for a non-digit or an overflow. */
static int rc_digit_step(u64* v, u8 c) {
  u64 d = (u8)(c - '0');
  if (d > 9 || *v > (~(u64)0 - d) / 10) {
    return 0;
  }
  *v = *v * 10 + d;
  return 1;
}

/* RFC 9110 8.6 / 4.1: 1*DIGIT into *v, 0 when s is empty, holds a
 * non-digit or overflows 64 bits (a huge value never wraps). */
int h3reqdrive_digits(wired_span s, u64* v) {
  *v = 0;
  for (usz i = 0; i < s.n; i++) {
    if (!rc_digit_step(v, s.p[i])) {
      return 0;
    }
  }
  return s.n != 0;
}

/* RFC 9114 4.4 / RFC 9220 3: a CONNECT that is not an Extended CONNECT. */
int h3reqdrive_plain_connect(const wired_h3reqdrive_req* r) {
  return h3_connect_is_method(r) && r->protocol == 0;
}

/* RFC 9114 4.4: a plain CONNECT carries :authority and neither :scheme nor
 * :path; every other request :method, :scheme and :path (4.3.1). Either
 * way no pseudo-header repeats, is unknown or follows a regular field. */
static int rc_ph_shape_ok(const h3_ph_set* p, const wired_h3reqdrive_req* r) {
  if (h3reqdrive_plain_connect(r)) {
    return p->ok && h3_connect_req_ok(r);
  }
  return h3_ph_request_ok(p);
}

/* RFC 9114 4.3 / 4.3.1: the request pseudo-headers are well formed, and
 * the response-only :status is absent. */
int h3reqdrive_ph_ok(const h3_ph_set* p, const wired_h3reqdrive_req* r) {
  return !(p->seen & (1u << H3_PH_STATUS)) && rc_ph_shape_ok(p, r);
}

/* RFC 9110 7.1 / RFC 9114 4.3.1: "*" (asterisk-form) belongs to OPTIONS
 * alone. */
static int rc_asterisk_ok(const wired_h3reqdrive_req* r) {
  return !h3reqdrive_span_is(wired_span_of(r->path, r->path_len), "*") ||
         h3reqdrive_span_is(wired_span_of(r->method, r->method_len), "OPTIONS");
}

/* RFC 9114 4.3.1: a present :path is never empty. */
static int rc_path_ok(const wired_h3reqdrive_req* r) {
  return !(r->path && !r->path_len) && rc_asterisk_ok(r);
}

/* RFC 9114 4.3.1 / 4.4, RFC 9110 4.2 / 7.1 / 9.3.6: the request target the
 * pseudo-headers and Host name is acceptable. */
static int rc_target_ok(const wired_h3reqdrive_req* r) {
  return rc_path_ok(r) && h3reqdrive_authority_ok(r);
}

/* RFC 9110 8.6: a Content-Length, if any, is 1*DIGIT (no 64-bit wrap,
 * 9110-012); it is kept in r for the streaming path to check too. */
static int rc_cl_take(wired_h3reqdrive_req* r) {
  wired_span v = wired_span_of(0, 0);
  if (!wired_http_req_header(
          r, wired_span_of((const u8*)"content-length", 14), &v)) {
    return 1;
  }
  r->has_content_length = 1;
  return h3reqdrive_digits(v, &r->content_length);
}

/* The STREAM frame carries the stream's end: every DATA frame is here. */
static int rc_whole(wired_span stream_data) {
  stream_frame f;
  return frame_get_stream(stream_data.p, stream_data.n, &f) && f.fin;
}

/* RFC 9114 4.1.2: compare the declared length with the whole body -- a
 * CONNECT stream's DATA is tunnel payload, not content (RFC 9110 9.3.6). */
static int rc_cl_applies(
    wired_span stream_data, const wired_h3reqdrive_req* r) {
  return r->has_content_length && rc_whole(stream_data) &&
         !h3_connect_is_method(r);
}

static int rc_cl_ok(wired_span stream_data, const wired_h3reqdrive_req* r) {
  return !rc_cl_applies(stream_data, r) ||
         h3_content_length_ok(r->content_length, r->data_len);
}

/* RFC 9114 4.1.2 / 4.3, RFC 9110 8.6: the request's control data and
 * Content-Length are acceptable; a mismatch with the DATA received is
 * malformed (9114-014, 9110-010). */
int h3reqdrive_request_ok(wired_span stream_data, wired_h3reqdrive_req* r) {
  return rc_target_ok(r) && rc_cl_take(r) && rc_cl_ok(stream_data, r);
}
