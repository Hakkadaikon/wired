#include "app/http3/request/h3reqdrive/request_drive_impl.h"

static int  is_request_pseudo(h3_ph_kind k);
static void take_priority(const rline* L, wired_h3reqdrive_req* r);
static void take_origin(const rline* L, wired_h3reqdrive_req* r);
static void take_wt_avail(const rline* L, wired_h3reqdrive_req* r);
static usz  cookie_sep_len(const wired_h3reqdrive_req* r);
static void cookie_join(wired_h3reqdrive_req* r, const u8* value, usz vlen);
static void take_cookie(const rline* L, wired_h3reqdrive_req* r);
static int  value_is_100_continue(const rline* L);
static void take_expect(const rline* L, wired_h3reqdrive_req* r);
static void classify_regular(const rline* L, wired_h3reqdrive_req* r);

usz h3reqdrive_decode_line(
    wired_span fs, wired_mspan scr, const qdyn_src* dyn, rline* L) {
  usz c = 0;
  for (usz i = 0; !c && i < 4; i++) c = line_forms[i](fs, scr, dyn, L);
  return c;
}

/* A request pseudo-header kind has a (value, len) slot in wired_h3reqdrive_req.
 */
static int is_request_pseudo(h3_ph_kind k) {
  return k >= H3_PH_METHOD && k <= H3_PH_PROTOCOL;
}

/* 1 if the recovered line's name is exactly the NUL-terminated s. */
int h3reqdrive_line_name_is(const rline* L, const char* s) {
  usz n    = h3reqdrive_cstr_len(s);
  u8  diff = (u8)(L->name_len != n);
  for (usz i = 0; i < n && i < L->name_len; i++) diff |= L->name[i] ^ (u8)s[i];
  return diff == 0;
}

/* RFC 9218 5: a regular `priority` header carries the request's priority
 * field value; other regular fields stay ignored. */
static void take_priority(const rline* L, wired_h3reqdrive_req* r) {
  if (h3reqdrive_line_name_is(L, "priority"))
    h3_priority_sfv(wired_span_of(L->value, L->value_len), &r->priority);
}

/* WebTransport draft-ietf-webtrans-http3-15 SS3.6 / RFC 9220 3: a regular
 * `origin` header carries the browser client's origin for the server to
 * validate. Same borrow-or-scratch view as any other recovered line; other
 * regular fields stay ignored. */
static void take_origin(const rline* L, wired_h3reqdrive_req* r) {
  if (!h3reqdrive_line_name_is(L, "origin")) return;
  r->origin     = L->value;
  r->origin_len = L->value_len;
}

/* WebTransport draft-ietf-webtrans-http3-15 SS3.4: a regular
 * `wt-available-protocols` header carries the client's subprotocol offer (an
 * RFC 8941 sf-list of sf-strings). Copied verbatim into r's own fixed buffer
 * (unlike origin's borrowed view, see request_drive.h); a value that does not
 * fit is dropped, leaving the offer absent. */
static void take_wt_avail(const rline* L, wired_h3reqdrive_req* r) {
  if (!h3reqdrive_line_name_is(L, "wt-available-protocols")) return;
  if (L->value_len > sizeof r->wt_avail) return;
  bytes_memcpy(r->wt_avail, L->value, L->value_len);
  r->wt_avail_len = L->value_len;
}

/* RFC 9114 4.2.1: reassemble multiple `cookie` field lines into a single
 * value joined by "; ", as if the peer had sent one HTTP/1.1-style Cookie
 * header. Isolated from wired_h3reqdrive_req's other field-capture helpers
 * (see take_origin/take_wt_avail) since it is the only one that must fold
 * several field lines into one slot instead of taking the latest. */
static usz cookie_sep_len(const wired_h3reqdrive_req* r) {
  return r->cookie_len ? 2 : 0;
}

static void cookie_join(wired_h3reqdrive_req* r, const u8* value, usz vlen) {
  usz sep = cookie_sep_len(r);
  usz cap = sizeof r->cookie - r->cookie_len;
  if (sep + vlen > cap) return;
  bytes_memcpy(r->cookie + r->cookie_len, "; ", sep);
  bytes_memcpy(r->cookie + r->cookie_len + sep, value, vlen);
  r->cookie_len += sep + vlen;
}

static void take_cookie(const rline* L, wired_h3reqdrive_req* r) {
  if (h3reqdrive_line_name_is(L, "cookie"))
    cookie_join(r, L->value, L->value_len);
}

/* RFC 9110 10.1.1: a regular `expect` field carrying exactly "100-continue"
 * requests a 100 (Continue) interim response before the client sends the
 * message body. Mirrors h3reqdrive_line_name_is's own diff-accumulation shape
 * (a single loop, no per-byte branch) to stay at one branch total. */
static int value_is_100_continue(const rline* L) {
  static const u8 want[] = "100-continue";
  usz             n      = sizeof want - 1;
  u8              diff   = (u8)(L->value_len != n);
  for (usz i = 0; i < n && i < L->value_len; i++) diff |= L->value[i] ^ want[i];
  return diff == 0;
}

static void take_expect(const rline* L, wired_h3reqdrive_req* r) {
  if (h3reqdrive_line_name_is(L, "expect") && value_is_100_continue(L))
    r->expect_continue = 1;
}

/* A regular (non-pseudo-header) field: at most priority (RFC 9218 5), origin
 * (WebTransport draft SS3.6), wt-available-protocols (WebTransport draft
 * SS3.4), cookie (RFC 9114 4.2.1, reassembled) and expect (RFC 9110 10.1.1)
 * are captured; anything else is ignored (RFC 9114 4.3.1). */
static void classify_regular(const rline* L, wired_h3reqdrive_req* r) {
  take_priority(L, r);
  take_origin(L, r);
  take_wt_avail(L, r);
  take_cookie(L, r);
  take_expect(L, r);
}

/* Store one recovered line into r if it is a request pseudo-header; regular
 * fields go through classify_regular. The slot tables are indexed by kind,
 * whose enum order matches the struct fields. */
void h3reqdrive_classify_line(const rline* L, wired_h3reqdrive_req* r) {
  const u8** val[] = {0,        &r->method,  &r->scheme, &r->authority,
                      &r->path, &r->protocol};
  usz*       len[] = {
      0,
      &r->method_len,
      &r->scheme_len,
      &r->authority_len,
      &r->path_len,
      &r->protocol_len};
  h3_ph_kind k = h3_ph_classify(L->name, L->name_len);
  if (!is_request_pseudo(k)) {
    classify_regular(L, r);
    return;
  }
  *val[k] = L->value;
  *len[k] = L->value_len;
}
