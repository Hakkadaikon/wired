#include "app/http3/request/h3reqdrive/request_drive_impl.h"

static int line_name_ok(const rline* L);
static int line_chars_ok(const rline* L);
static int rd_ows(u8 c);
static usz rd_ows_lead(const u8* p, usz n);
static usz rd_ows_trail(const u8* p, usz n);
static int line_smuggling_ok(const rline* L);
static usz rd_copy(rd_cursor* cur, const u8* p, usz n);
static usz rd_pos(rd_cursor* cur, const u8* p, usz n);
static int rd_place(rd_cursor* cur, const u8* p, usz n, u16* pos);
static int rd_place_line(
    rd_cursor* cur, const rline* L, wired_h3reqdrive_hdr* h);
static int  rd_keeps(const rline* L, const wired_h3reqdrive_req* r);
static void rd_record(rd_cursor* cur, const rline* L, wired_h3reqdrive_req* r);

/* RFC 9114 4.2 / 10.3, RFC 9110 5.1: a regular field name is a lowercase
 * token; a pseudo-header name is left to the section's pseudo-header check
 * (an unknown one is malformed there). */
static int line_name_ok(const rline* L) {
  return h3_ph_classify(L->name, L->name_len) != H3_PH_NONE ||
         (h3_header_token_ok(L->name, L->name_len) &&
          h3_header_name_ok(L->name, L->name_len));
}

/* RFC 9114 10.3, RFC 9110 5.5: the name is valid and the value holds only
 * field-content octets (so never CR, LF or NUL) -- a line failing either is
 * malformed regardless of how it was encoded. */
static int line_chars_ok(const rline* L) {
  return line_name_ok(L) && h3_header_value_ok(L->value, L->value_len);
}

/* RFC 9114 4.1 / 4.2: request-smuggling defenses that key off the field
 * name -- Transfer-Encoding and the HTTP/1.1 connection-specific fields
 * (Connection, Keep-Alive, Proxy-Connection, Upgrade) are always malformed,
 * and a TE field's value must be exactly "trailers". */
static int line_smuggling_ok(const rline* L) {
  if (h3_header_name_forbidden(L->name, L->name_len)) {
    return 0;
  }
  if (!h3reqdrive_line_name_is(L, "te")) {
    return 1;
  }
  return h3_header_te_ok(L->value, L->value_len);
}

/* Decode failure or any malformed-line check on the recovered line. */
int h3reqdrive_line_ok(const rline* L) {
  return line_chars_ok(L) && line_smuggling_ok(L);
}

/* RFC 9110 5.6.3: OWS is SP or HTAB. */
static int rd_ows(u8 c) { return c == ' ' || c == '\t'; }

static usz rd_ows_lead(const u8* p, usz n) {
  usz i = 0;
  while (i < n && rd_ows(p[i])) {
    i++;
  }
  return i;
}

static usz rd_ows_trail(const u8* p, usz n) {
  usz i = 0;
  while (i < n && rd_ows(p[n - 1 - i])) {
    i++;
  }
  return i;
}

/* RFC 9110 5.5: a field value excludes its leading and trailing whitespace
 * before it is evaluated. */
void h3reqdrive_line_trim(rline* L) {
  usz lead = rd_ows_lead(L->value, L->value_len);
  L->value += lead;
  L->value_len -= lead;
  L->value_len -= rd_ows_trail(L->value, L->value_len);
}

/* Copy n octets to cur's unused scratch tail. Returns their position, or
 * (usz)-1 if they do not fit. */
static usz rd_copy(rd_cursor* cur, const u8* p, usz n) {
  usz at = cur->used;
  if (n > cur->scr.n - at) {
    return (usz)-1;
  }
  bytes_memcpy(cur->scr.p + at, p, n);
  cur->used += n;
  return at;
}

/* Position of p's n octets inside cur's scratch: where the line decoder
 * already wrote them, else a fresh copy (a static- or dynamic-table view;
 * RFC 9204 2.1.1/3.2: a dynamic entry may change after this decode). */
static usz rd_pos(rd_cursor* cur, const u8* p, usz n) {
  usz at = (usz)p - (usz)cur->scr.p;
  if (at < cur->scr.n) {
    return at;
  }
  return rd_copy(cur, p, n);
}

/* Place p's n octets in scratch with *pos set; 0 if they do not fit or the
 * position overflows wired_h3reqdrive_hdr's u16 fields. */
static int rd_place(rd_cursor* cur, const u8* p, usz n, u16* pos) {
  usz at = rd_pos(cur, p, n);
  *pos   = (u16)at;
  return at < 0x10000 && n < 0x10000 - at;
}

static int rd_place_line(
    rd_cursor* cur, const rline* L, wired_h3reqdrive_hdr* h) {
  return rd_place(cur, L->name, L->name_len, &h->name_off) &&
         rd_place(cur, L->value, L->value_len, &h->value_off);
}

/* Regular headers whose value wired_h3reqdrive_req already exposes in a
 * dedicated field: wired_http_req_header serves them from there (cookie
 * already joined, RFC 9114 4.2.1), so they spend no hdrs slot. */
const char* const rd_dedicated[] = {
    "cookie", "origin", "wt-available-protocols"};

/* 1 if a is exactly the NUL-terminated s. */
int h3reqdrive_span_is(wired_span a, const char* s) {
  usz n = wired_cstr_len(s);
  return a.n == n && ct_diffn(a.p, (const u8*)s, n) == 0;
}

/* Index of name in rd_dedicated, RD_DEDICATED_N if it is not one. */
usz h3reqdrive_rd_dedicated_idx(wired_span name) {
  usz i = 0;
  while (i < RD_DEDICATED_N && !h3reqdrive_span_is(name, rd_dedicated[i])) {
    i++;
  }
  return i;
}

static int rd_keeps(const rline* L, const wired_h3reqdrive_req* r) {
  return r->hdr_count < WIRED_H3REQDRIVE_MAX_HDRS &&
         h3_ph_classify(L->name, L->name_len) == H3_PH_NONE &&
         h3reqdrive_rd_dedicated_idx(wired_span_of(L->name, L->name_len)) ==
             RD_DEDICATED_N;
}

/* RFC 9114 4.2: keep a regular header line for wired_http_req_header. */
static void rd_record(rd_cursor* cur, const rline* L, wired_h3reqdrive_req* r) {
  wired_h3reqdrive_hdr* h;
  if (!rd_keeps(L, r)) {
    return;
  }
  h            = &r->hdrs[r->hdr_count];
  h->name_len  = (u16)L->name_len;
  h->value_len = (u16)L->value_len;
  if (rd_place_line(cur, L, h)) {
    r->hdr_count++;
  }
}

/* Decode one line at cur->off into r, advancing cur. Returns 1 ok, 0 on a
 * malformed line (decode failure or a forbidden CR/LF/NUL octet). */
int h3reqdrive_step_line(rd_cursor* cur, wired_h3reqdrive_req* r) {
  rline      L    = {0};
  wired_span rest = wired_span_of(cur->fs.p + cur->off, cur->fs.n - cur->off);
  usz        c    = h3reqdrive_decode_line(
      rest, wired_mspan_of(cur->scr.p + cur->used, cur->scr.n - cur->used),
      &cur->dyn, &L);
  /* RFC 9204 2.2.3: a reference to no live entry (unresolvable or
   * evicted) fails the connection. Any other line this decoder cannot
   * decode -- one too large for its scratch or name cap (RFC 9204 7.4) --
   * only rejects the request, like a well-encoded line HTTP/3 rejects. */
  r->qpack_failed = L.ref_bad;
  if (!c) {
    return 0;
  }
  h3reqdrive_line_trim(&L);
  if (!h3reqdrive_line_ok(&L)) {
    return 0;
  }
  h3_ph_field(&cur->ph, L.name, L.name_len);
  h3reqdrive_classify_line(&L, r);
  cur->off += c;
  cur->used += L.scratch_used;
  rd_record(cur, &L, r);
  return 1;
}

/* Walk field lines from cur->off to cur->fs.n into r. Returns 1 ok, 0 on a
 * malformed line. */
int h3reqdrive_scan_lines(rd_cursor* cur, wired_h3reqdrive_req* r) {
  while (cur->off < cur->fs.n) {
    if (!h3reqdrive_step_line(cur, r)) {
      return 0;
    }
  }
  return 1;
}
