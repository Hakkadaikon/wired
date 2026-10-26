#include "app/http3/server/srvrun/srvrun_impl.h"
#include "common/bytes/text/text.h"
#include "common/fmt/fmt.h"

static void srvrun_hdrs_add(srvrun_hdrs* h, wired_span name, wired_span value);
static int  srvrun_hdr_name_is(const qpack_field* f, wired_span name);
static int  srvrun_hdrs_has(const srvrun_hdrs* h, wired_span name);
static u64  srvrun_date_secs(void);
static void srvrun_hdrs_date(srvrun_hdrs* h);
static void srvrun_hdrs_sdk(srvrun_hdrs* h, int with_len, u64 len);
static int  srvrun_req_method_is(const wired_h3reqdrive_req* r, const char* m);
static int  srvrun_connect_2xx(const wired_h3reqdrive_req* r, u16 status);
static int  srvrun_app_len_ok(const wired_http_exchange* x);
static const char* srvrun_status_ct(wired_span body);
static void        srvrun_hdrs_allow(srvrun_hdrs* h, u16 status);
static void        srvrun_hdrs_extra(srvrun_hdrs* h, const qpack_field* extra);

static const u8 srvrun_hdr_date_n[]  = {'d', 'a', 't', 'e'};
static const u8 srvrun_hdr_cl_n[]    = {'c', 'o', 'n', 't', 'e', 'n', 't',
                                        '-', 'l', 'e', 'n', 'g', 't', 'h'};
static const u8 srvrun_hdr_allow_n[] = {'a', 'l', 'l', 'o', 'w'};

/* RFC 9110 15.5 / 15.6: the explanation the SDK sends with the 4xx/5xx
 * responses it generates itself; any other status gets the generic one. */
static const struct {
  u16         status;
  const char* text;
} srvrun_status_texts[] = {
    {403, "Forbidden\n"},
    {404, "Not Found\n"},
    {405, "Method Not Allowed\n"},
    {413, "Content Too Large\n"},
    {429, "Too Many Requests\n"},
    {431, "Request Header Fields Too Large\n"},
    {500, "Internal Server Error\n"},
    {501, "Not Implemented\n"},
};

static void srvrun_hdrs_add(srvrun_hdrs* h, wired_span name, wired_span value) {
  h->f[h->n++] = (qpack_field){name, value};
}

static int srvrun_hdr_name_is(const qpack_field* f, wired_span name) {
  return f->name.n == name.n && srvrun_wt_bytes_eq(f->name.p, name.p, name.n);
}

/* Field names are lowercase tokens by now (srvrun_http_fields_ok), so an
 * exact compare is the case-insensitive one. */
static int srvrun_hdrs_has(const srvrun_hdrs* h, wired_span name) {
  for (usz i = 0; i < h->n; i++) {
    if (srvrun_hdr_name_is(&h->f[i], name)) {
      return 1;
    }
  }
  return 0;
}

/* Test-only pin for the Date clock (0 = the live wall clock), so a test can
 * rebuild a response's exact bytes; the same override-flag shape as
 * srvrun_test_force_challenge_rng_fail. Reset to 0 after the owning test. */
static u64 g_srvrun_date_pin;

__attribute__((unused)) static void srvrun_test_pin_date(u64 secs) {
  g_srvrun_date_pin = secs;
}

static u64 srvrun_date_secs(void) {
  return g_srvrun_date_pin ? g_srvrun_date_pin : wired_clock_epoch_secs();
}

/* RFC 9110 6.6.1: an origin server with a clock sends Date (IMF-fixdate,
 * 5.6.7); a failed clock read (0) means no clock, so no Date. An
 * application-supplied date is kept as the only one (RFC 9110 5.3). */
static void srvrun_hdrs_date(srvrun_hdrs* h) {
  u64        secs = srvrun_date_secs();
  wired_span n    = wired_span_of(srvrun_hdr_date_n, sizeof srvrun_hdr_date_n);
  if (!secs || srvrun_hdrs_has(h, n)) {
    return;
  }
  clock_imf_fixdate(secs, h->date);
  srvrun_hdrs_add(h, n, wired_span_of(h->date, sizeof h->date));
}

/* RFC 9110 8.6: Content-Length when the size is known up front (with_len;
 * HTTP/3 fixes the DATA length before the HEADERS go out), unless the
 * application set one itself; then Date. */
static void srvrun_hdrs_sdk(srvrun_hdrs* h, int with_len, u64 len) {
  wired_span n = wired_span_of(srvrun_hdr_cl_n, sizeof srvrun_hdr_cl_n);
  if (with_len && !srvrun_hdrs_has(h, n)) {
    usz k = wired_snprintf(
        (char*)h->len, sizeof h->len, "%llu", (unsigned long long)len);
    srvrun_hdrs_add(h, n, wired_span_of(h->len, k));
  }
  srvrun_hdrs_date(h);
}

/* :method equals m exactly (RFC 9110 9.1: case-sensitive). */
static int srvrun_req_method_is(const wired_h3reqdrive_req* r, const char* m) {
  usz n = wired_cstr_len(m);
  if (!r->method || r->method_len != n) {
    return 0;
  }
  return srvrun_wt_bytes_eq(r->method, (const u8*)m, n);
}

/* RFC 9110 9.3.6: a 2xx to CONNECT is a tunnel, never Content-Length. */
static int srvrun_connect_2xx(const wired_h3reqdrive_req* r, u16 status) {
  return status / 100 == 2 && srvrun_req_method_is(r, "CONNECT");
}

/* RFC 9110 8.6 (9110-013): no Content-Length on 204/304, on a 2xx to
 * CONNECT, or for HEAD, whose value would have to be the GET body's
 * length, which this exchange never produced. */
static int srvrun_app_len_ok(const wired_http_exchange* x) {
  u16 s = srvrun_http_status(x);
  return !srvrun_http_status_bodiless(s) && !srvrun_req_is_head(x->req) &&
         !srvrun_connect_2xx(x->req, s);
}

int srvrun_req_is_head(const wired_h3reqdrive_req* r) {
  return srvrun_req_method_is(r, "HEAD");
}

const char* srvrun_status_text(u16 status) {
  for (usz i = 0; i < sizeof srvrun_status_texts / sizeof *srvrun_status_texts;
       i++) {
    if (srvrun_status_texts[i].status == status) {
      return srvrun_status_texts[i].text;
    }
  }
  return "Error\n";
}

/* RFC 9110 15.5 / 15.6: the body of an SDK-generated status response --
 * the explanation for a 4xx/5xx to anything but HEAD, else none. */
wired_span srvrun_status_body(const wired_h3reqdrive_req* r, u16 status) {
  if (status < 400 || srvrun_req_is_head(r)) {
    return wired_span_of(0, 0);
  }
  return wired_span_cstr(srvrun_status_text(status));
}

static const char* srvrun_status_ct(wired_span body) {
  return body.n ? "text/plain" : 0;
}

/* The application's fields followed by the SDK's own (Content-Length,
 * Date) for a wired_http_handler response with total_len body bytes. */
h3resp_fields srvrun_hdrs_app(
    srvrun_hdrs* h, const wired_http_exchange* x, u64 total_len) {
  h->n = 0;
  for (usz i = 0; i < x->field_count; i++) {
    srvrun_hdrs_add(h, x->fields[i].name, x->fields[i].value);
  }
  srvrun_hdrs_sdk(h, srvrun_app_len_ok(x), total_len);
  return (h3resp_fields){h->f, h->n};
}

/* RFC 9110 10.2.1 / 15.5.6: a 405 carries Allow, the methods
 * h3_method_is_allowed lets through. */
static void srvrun_hdrs_allow(srvrun_hdrs* h, u16 status) {
  wired_span n = wired_span_of(srvrun_hdr_allow_n, sizeof srvrun_hdr_allow_n);
  if (status != 405) {
    return;
  }
  srvrun_hdrs_add(h, n, h3_method_allow_list(h->allow, sizeof h->allow));
}

static void srvrun_hdrs_extra(srvrun_hdrs* h, const qpack_field* extra) {
  if (extra) {
    srvrun_hdrs_add(h, extra->name, extra->value);
  }
}

/* An SDK-generated status response for req into out: HEADERS (:status,
 * extra when given, Allow on a 405, Content-Length, Date) plus, for a
 * 4xx/5xx, a DATA frame explaining it (srvrun_status_body). Content-Length
 * is left off a 2xx: every status-only 2xx answers a CONNECT. Returns 0 if
 * out lacks room. */
int srvrun_status_build(
    const wired_h3reqdrive_req* req,
    u16                         status,
    const qpack_field*          extra,
    wired_obuf*                 out) {
  srvrun_hdrs            h    = {0};
  wired_span             body = srvrun_status_body(req, status);
  qpackenc_status_result unused;
  usz                    off;
  srvrun_hdrs_extra(&h, extra);
  srvrun_hdrs_allow(&h, status);
  srvrun_hdrs_sdk(&h, status >= 300, body.n);
  if (!h3resp_prefix_fields_qenc(
          status, srvrun_status_ct(body), body.n, (h3resp_fields){h.f, h.n}, 0,
          &unused, out)) {
    return 0;
  }
  off = out->len;
  if (!bytes_put(wired_mspan_of(out->p, out->cap), &off, body)) {
    return 0;
  }
  out->len = off;
  return 1;
}
