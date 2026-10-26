#include "app/http3/request/h3reqdrive/request_drive_impl.h"

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
static int rc_host_port_ok(wired_span a);
static int rc_connect_target_ok(const wired_h3reqdrive_req* r);

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

/* host ":" port with a non-empty host; a.p is non-null. */
static int rc_host_port_ok(wired_span a) {
  usz c = rc_after_last_colon(a);
  return c > 1 && rc_port_ok(wired_span_of(a.p + c, a.n - c));
}

/* RFC 9110 9.3.6 (9110-043): a plain CONNECT's authority-form target is
 * host ":" port, with a non-empty host and a valid port. */
static int rc_connect_target_ok(const wired_h3reqdrive_req* r) {
  return !h3reqdrive_plain_connect(r) ||
         (r->authority &&
          rc_host_port_ok(wired_span_of(r->authority, r->authority_len)));
}

/* RFC 9114 4.3.1 / 4.4, RFC 9110 4.2 / 9.3.6: :authority and Host name an
 * acceptable target -- the CONNECT authority-form included. */
int h3reqdrive_authority_ok(const wired_h3reqdrive_req* r) {
  return rc_authority_ok(r) && rc_connect_target_ok(r);
}
