#include "app/http3/request/h3reqdrive/request_drive_impl.h"

static int rc_digit_step(u64* v, u8 c);
static int rc_plain_connect(const wired_h3reqdrive_req* r);
static int rc_ph_shape_ok(const h3_ph_set* p, const wired_h3reqdrive_req* r);
static int rc_asterisk_ok(const wired_h3reqdrive_req* r);
static int rc_path_ok(const wired_h3reqdrive_req* r);
static int rc_has_at(wired_span a);
static int rc_host_named(wired_span a);
static int rc_value_ok(int has, wired_span a);
static int rc_mandatory_authority(const wired_h3reqdrive_req* r);
static int rc_present_ok(const wired_h3reqdrive_req* r, int has_host);
static int rc_same(const wired_h3reqdrive_req* r, wired_span host);
static int rc_match_ok(
    const wired_h3reqdrive_req* r, int has_host, wired_span host);
static int rc_values_ok(
    const wired_h3reqdrive_req* r, int has_host, wired_span host);
static int rc_authority_ok(const wired_h3reqdrive_req* r);
static usz rc_after_last_colon(wired_span a);
static int rc_port_len_ok(usz n);
static int rc_port_value_ok(u64 v);
static int rc_port_ok(wired_span p);
static int rc_connect_target_ok(const wired_h3reqdrive_req* r);

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
static int rc_plain_connect(const wired_h3reqdrive_req* r) {
  return h3_connect_is_method(r) && r->protocol == 0;
}

/* RFC 9114 4.4: a plain CONNECT carries :authority and neither :scheme nor
 * :path; every other request :method, :scheme and :path (4.3.1). Either
 * way no pseudo-header repeats, is unknown or follows a regular field. */
static int rc_ph_shape_ok(const h3_ph_set* p, const wired_h3reqdrive_req* r) {
  if (rc_plain_connect(r)) {
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

static int rc_has_at(wired_span a) {
  for (usz i = 0; i < a.n; i++) {
    if (a.p[i] == '@') {
      return 1;
    }
  }
  return 0;
}

/* RFC 9114 4.3.1 / RFC 9110 4.2.1: a non-empty host and no userinfo. */
static int rc_host_named(wired_span a) {
  return a.n != 0 && a.p[0] != ':' && !rc_has_at(a);
}

/* An absent :authority or Host passes; a present one is rc_host_named. */
static int rc_value_ok(int has, wired_span a) {
  return !has || rc_host_named(a);
}

/* RFC 9114 4.3.1: "http" and "https" have a mandatory authority. */
static int rc_mandatory_authority(const wired_h3reqdrive_req* r) {
  wired_span s = wired_span_of(r->scheme, r->scheme_len);
  return h3reqdrive_span_is(s, "https") || h3reqdrive_span_is(s, "http");
}

/* RFC 9114 4.3.1: such a scheme carries :authority or Host. */
static int rc_present_ok(const wired_h3reqdrive_req* r, int has_host) {
  return r->authority || has_host || !rc_mandatory_authority(r);
}

static int rc_same(const wired_h3reqdrive_req* r, wired_span host) {
  return host.n == r->authority_len &&
         ct_diffn(host.p, r->authority, host.n) == 0;
}

/* RFC 9114 4.3.1: both present, they carry the same value. */
static int rc_match_ok(
    const wired_h3reqdrive_req* r, int has_host, wired_span host) {
  return !r->authority || !has_host || rc_same(r, host);
}

static int rc_values_ok(
    const wired_h3reqdrive_req* r, int has_host, wired_span host) {
  return rc_value_ok(
             r->authority != 0,
             wired_span_of(r->authority, r->authority_len)) &&
         rc_value_ok(has_host, host);
}

/* RFC 9114 4.3.1 / RFC 9110 4.2: the :authority and Host rules. */
static int rc_authority_ok(const wired_h3reqdrive_req* r) {
  wired_span host = wired_span_of(0, 0);
  int        has_host =
      wired_http_req_header(r, wired_span_of((const u8*)"host", 4), &host);
  return rc_values_ok(r, has_host, host) && rc_present_ok(r, has_host) &&
         rc_match_ok(r, has_host, host);
}

/* Offset just past a's last ':', 0 when it has none. */
static usz rc_after_last_colon(wired_span a) {
  usz i = a.n;
  while (i > 0 && a.p[i - 1] != ':') {
    i--;
  }
  return i;
}

static int rc_port_len_ok(usz n) { return n >= 1 && n <= 5; }

static int rc_port_value_ok(u64 v) { return v >= 1 && v <= 65535; }

/* RFC 3986 3.2.3 / RFC 9110 4.2: port = *DIGIT, here one TCP/UDP port. */
static int rc_port_ok(wired_span p) {
  u64 v = 0;
  return rc_port_len_ok(p.n) && h3reqdrive_digits(p, &v) && rc_port_value_ok(v);
}

/* RFC 9110 9.3.6 (9110-043): a plain CONNECT's authority-form target is
 * host ":" port, with a non-empty host and a valid port. */
static int rc_connect_target_ok(const wired_h3reqdrive_req* r) {
  wired_span a = wired_span_of(r->authority, r->authority_len);
  usz        c = rc_after_last_colon(a);
  if (!rc_plain_connect(r)) {
    return 1;
  }
  return c > 1 && rc_port_ok(wired_span_of(a.p + c, a.n - c));
}

/* RFC 9114 4.3.1 / 4.4, RFC 9110 4.2 / 7.1 / 9.3.6: the request target the
 * pseudo-headers and Host name is acceptable. */
int h3reqdrive_target_ok(const wired_h3reqdrive_req* r) {
  return rc_path_ok(r) && rc_authority_ok(r) && rc_connect_target_ok(r);
}
