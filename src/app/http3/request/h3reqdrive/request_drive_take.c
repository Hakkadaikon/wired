#include "app/http3/request/h3reqdrive/request_drive_impl.h"

static int  is_request_pseudo(h3_ph_kind k);
static void take_priority(const rline* L, wired_h3reqdrive_req* r);
static void take_origin(const rline* L, wired_h3reqdrive_req* r);
static void take_wt_avail(const rline* L, wired_h3reqdrive_req* r);
static int  field_join(
    u8* buf, usz cap, usz* len, const char* sep, wired_span v);
static void take_cookie(const rline* L, wired_h3reqdrive_req* r);
static int  value_is_100_continue(const rline* L);
static void take_expect(const rline* L, wired_h3reqdrive_req* r);
static void classify_regular(const rline* L, wired_h3reqdrive_req* r);

usz h3reqdrive_decode_line(
    wired_span fs, wired_mspan scr, const qdyn_src* dyn, rline* L) {
  usz c = 0;
  for (usz i = 0; !c && i < 4; i++) {
    c = line_forms[i](fs, scr, dyn, L);
  }
  return c;
}

/* RFC 9114 4.2.2 / RFC 9110 15.5.20: a section larger than this decoder
 * holds is answered 431. Every other field is cleared, views into the
 * scratch included, so no request with a field left out goes further; the
 * server cancels the stream's QPACK references (RFC 9204 2.2.2.2). */
void h3reqdrive_too_large(wired_h3reqdrive_req* r) {
  *r = (wired_h3reqdrive_req){.too_large_status = 431};
}

/* RFC 9114 4.2.2 / RFC 9204 7.4: why the line at rest failed to decode.
 * One that fits the whole scratch (re-decoded there: the request is
 * dropped, so earlier lines' bytes may go) failed only for the room
 * earlier lines took -- the section is past the advertised
 * SETTINGS_MAX_FIELD_SECTION_SIZE, answered 431 -- r is cleared, its views
 * into the re-used scratch included, so only too_large_status remains.
 * Anything else (a line larger than the scratch alone, a bad encoding) is
 * the stream error QPACK_DECOMPRESSION_FAILED. */
void h3reqdrive_line_fail(
    rd_cursor* cur, wired_span rest, wired_h3reqdrive_req* r) {
  rline L = {0};
  if (h3reqdrive_decode_line(rest, cur->scr, &cur->dyn, &L)) {
    h3reqdrive_too_large(r);
    return;
  }
  r->reject_code = QPACK_DECOMPRESSION_FAILED;
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
  for (usz i = 0; i < n && i < L->name_len; i++) {
    diff |= L->name[i] ^ (u8)s[i];
  }
  return diff == 0;
}

/* RFC 9218 5: a regular `priority` header carries the request's priority
 * field value; other regular fields stay ignored. */
static void take_priority(const rline* L, wired_h3reqdrive_req* r) {
  if (h3reqdrive_line_name_is(L, "priority")) {
    h3_priority_sfv(wired_span_of(L->value, L->value_len), &r->priority);
  }
}

/* WebTransport draft-ietf-webtrans-http3-15 SS3.6 / RFC 9220 3: a regular
 * `origin` header carries the browser client's origin for the server to
 * validate. Same borrow-or-scratch view as any other recovered line. A
 * second origin line never reaches here: it is malformed (rd_line_admits). */
static void take_origin(const rline* L, wired_h3reqdrive_req* r) {
  if (!h3reqdrive_line_name_is(L, "origin")) {
    return;
  }
  r->origin     = L->value;
  r->origin_len = L->value_len;
}

/* RFC 9110 5.3: append value v to the list held in buf[0..*len) after the
 * 2-octet sep (none before the first item); 0 if it would not fit cap. */
static int field_join(
    u8* buf, usz cap, usz* len, const char* sep, wired_span v) {
  usz s = *len ? 2 : 0;
  if (s + v.n > cap - *len) {
    return 0;
  }
  bytes_memcpy(buf + *len, sep, s);
  bytes_memcpy(buf + *len + s, v.p, v.n);
  *len += s + v.n;
  return 1;
}

/* WebTransport draft-ietf-webtrans-http3-15 SS3.4: a regular
 * `wt-available-protocols` header carries the client's subprotocol offer (an
 * RFC 8941 sf-list of sf-strings). Copied into r's own fixed buffer (unlike
 * origin's borrowed view, see request_drive.h); several lines are one list
 * joined with ", " (RFC 9110 5.3), and an offer that does not fit fails the
 * request with 431 (RFC 9114 4.2.2) instead of losing a line. */
static void take_wt_avail(const rline* L, wired_h3reqdrive_req* r) {
  if (!h3reqdrive_line_name_is(L, "wt-available-protocols")) {
    return;
  }
  if (!field_join(
          r->wt_avail, sizeof r->wt_avail, &r->wt_avail_len, ", ",
          wired_span_of(L->value, L->value_len))) {
    r->too_large_status = 431;
  }
}

/* RFC 9114 4.2.1: reassemble multiple `cookie` field lines into a single
 * value joined by "; ", as if the peer had sent one HTTP/1.1-style Cookie
 * header. A crumb that would not fit fails the request with 431 (RFC 9114
 * 4.2.2) instead of being dropped. */
static void take_cookie(const rline* L, wired_h3reqdrive_req* r) {
  if (h3reqdrive_line_name_is(L, "cookie") &&
      !field_join(
          r->cookie, sizeof r->cookie, &r->cookie_len, "; ",
          wired_span_of(L->value, L->value_len))) {
    r->too_large_status = 431;
  }
}

/* RFC 9110 10.1.1: a regular `expect` field carrying exactly "100-continue"
 * requests a 100 (Continue) interim response before the client sends the
 * message body. Mirrors h3reqdrive_line_name_is's own diff-accumulation shape
 * (a single loop, no per-byte branch) to stay at one branch total. */
static int value_is_100_continue(const rline* L) {
  static const u8 want[] = "100-continue";
  usz             n      = sizeof want - 1;
  u8              diff   = (u8)(L->value_len != n);
  for (usz i = 0; i < n && i < L->value_len; i++) {
    diff |= L->value[i] ^ want[i];
  }
  return diff == 0;
}

static void take_expect(const rline* L, wired_h3reqdrive_req* r) {
  if (h3reqdrive_line_name_is(L, "expect") && value_is_100_continue(L)) {
    r->expect_continue = 1;
  }
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
