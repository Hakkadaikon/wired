#include "app/http3/request/h3reqdrive/request_drive.h"

#include "app/http3/core/h3/headercase.h"
#include "app/http3/core/h3/priupdate.h"
#include "app/http3/core/h3/pseudoheader.h"
#include "app/http3/core/h3conn/request.h"
#include "app/http3/request/h3reqdrive/request_parse.h"
#include "app/http3/request/h3reqenc/request_headers.h"
#include "app/qpack/qpack/base.h"
#include "app/qpack/qpack/error.h"
#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/insertcount.h"
#include "app/qpack/qpack/literal.h"
#include "app/qpack/qpack/prefix.h"
#include "app/qpack/qpack/static_table.h"
#include "app/qpack/qpackdyn/field_decode.h"
#include "common/bytes/util/bytes.h"

/* RFC 9114 4.1 / 4.3.1, RFC 9204 4.5 */
int wired_h3reqdrive_send_method(
    u64 stream_id, const wired_h3reqdrive_send_in* in, wired_obuf* out) {
  u8               fs[256];
  wired_obuf       fsb = obuf_of(fs, sizeof(fs));
  h3req_headers_in hin = {in->path, in->authority};
  h3conn_req_in    rin;
  if (!h3req_enc_method(in->method, &hin, &fsb)) return 0;
  rin = (h3conn_req_in){wired_span_of(fs, fsb.len), in->body};
  return h3conn_send_request(stream_id, &rin, out);
}

/* RFC 9114 4.1 / 4.3.1, RFC 9204 4.5 */
int wired_h3reqdrive_send_get(
    u64 stream_id, const wired_h3reqdrive_get_in* in, wired_obuf* out) {
  static const u8          method[] = {'G', 'E', 'T'};
  wired_h3reqdrive_send_in sin      = {
      wired_span_of(method, 3), in->path, in->authority, wired_span_of(0, 0)};
  return wired_h3reqdrive_send_method(stream_id, &sin, out);
}

/* One recovered field line: name and value, each borrowed from the static
 * table or copied into the caller's scratch. */
typedef struct {
  const u8* name;
  usz       name_len;
  const u8* value;
  usz       value_len;
  usz scratch_used; /* scratch octets this line occupies (0 if borrowed) */
} rline;

/* Length of a NUL-terminated static-table string. */
static usz cstr_len(const char* s) {
  usz i = 0;
  while (s[i]) i++;
  return i;
}

/* Borrow a dynamic-table field's name/value view into L (RFC 9204 3.2.4). */
static void borrow_dynamic(const qpack_field* f, rline* L) {
  L->name         = f->name.p;
  L->name_len     = f->name.n;
  L->value        = f->value.p;
  L->value_len    = f->value.n;
  L->scratch_used = 0;
}

/* RFC 9204 4.5.2 / 4.5.3: an Indexed Field Line or Indexed Field Line with
 * Post-Base Index -> the referenced entry's name and value, dynamic-table
 * (T=0, or the post-Base form, always dynamic) references resolved against
 * dyn->table when set; a caller with no dynamic table (dyn->table == 0, e.g.
 * no encoder stream has been seen yet) simply cannot resolve one, matching
 * this decoder's prior static-table-only behavior. */
static usz line_indexed(wired_span fs, const qdyn_src* dyn, rline* L) {
  qpack_field f;
  usz         consumed;
  qdyn_src    src = {dyn->table, dyn->base, fs};
  if (!qdyn_decode_field(&src, &f, &consumed)) return 0;
  borrow_dynamic(&f, L);
  return consumed;
}

/* RFC 9204 4.5.4: a Literal With Name Reference -> static name, copied value.
 */
static usz line_namref(wired_span fs, wired_mspan scr, rline* L) {
  qpack_nameref r    = {0, 0, 0};
  wired_obuf    vb   = obuf_of(scr.p, scr.n);
  const char *  name = 0, *value = 0;
  usz           c = qpack_literal_namref_decode(fs, &r, &vb);
  if (!c || !qpack_static_get((usz)r.index, &name, &value)) return 0;
  L->name         = (const u8*)name;
  L->name_len     = cstr_len(name);
  L->value        = scr.p;
  L->value_len    = vb.len;
  L->scratch_used = vb.len;
  return c;
}

/* Field names are short (RFC 9110 5.1's token grammar, the longest ones this
 * codebase decodes -- e.g. "wt-available-protocols" -- run well under this);
 * capping the name's share leaves the rest of scr for the value, which can
 * run much longer (e.g. a multi-entry subprotocol offer list). */
#define LITNAME_NAME_CAP 64

static usz litname_split(usz scr_n) {
  return scr_n > LITNAME_NAME_CAP ? LITNAME_NAME_CAP : scr_n / 2;
}

/* RFC 9204 4.5.6: a Literal With Literal Name -> name in the first (capped)
 * scratch share, value in the rest (disjoint, both written in one call). */
static usz line_litname(wired_span fs, wired_mspan scr, rline* L) {
  int            never = 0;
  usz            half  = litname_split(scr.n);
  qpack_fieldbuf fb    = {
      obuf_of(scr.p, half), obuf_of(scr.p + half, scr.n - half)};
  usz c = qpack_literal_name_decode(fs, &never, &fb);
  if (!c) return 0;
  L->name         = scr.p;
  L->name_len     = fb.name.len;
  L->value        = scr.p + half;
  L->value_len    = fb.value.len;
  L->scratch_used = half + fb.value.len;
  return c;
}

/* RFC 9204 4.5: decode one field line of any of the four forms this decoder
 * supports (Indexed/Post-Base Indexed via dyn, Literal With Name Reference
 * and Literal With Literal Name are static-table/copied-value only -- see
 * line_namref/line_litname's own docs). */
static usz decode_line(
    wired_span fs, wired_mspan scr, const qdyn_src* dyn, rline* L) {
  usz c = line_indexed(fs, dyn, L);
  if (c) return c;
  c = line_namref(fs, scr, L);
  if (c) return c;
  return line_litname(fs, scr, L);
}

/* A request pseudo-header kind has a (value, len) slot in wired_h3reqdrive_req.
 */
static int is_request_pseudo(h3_ph_kind k) {
  return k >= QUIC_H3_PH_METHOD && k <= QUIC_H3_PH_PROTOCOL;
}

/* 1 if the recovered line's name is exactly the NUL-terminated s. */
static int line_name_is(const rline* L, const char* s) {
  usz n    = cstr_len(s);
  u8  diff = (u8)(L->name_len != n);
  for (usz i = 0; i < n && i < L->name_len; i++) diff |= L->name[i] ^ (u8)s[i];
  return diff == 0;
}

/* RFC 9218 5: a regular `priority` header carries the request's priority
 * field value; other regular fields stay ignored. */
static void take_priority(const rline* L, wired_h3reqdrive_req* r) {
  if (line_name_is(L, "priority"))
    h3_priority_sfv(wired_span_of(L->value, L->value_len), &r->priority);
}

/* WebTransport draft-ietf-webtrans-http3-15 SS3.6 / RFC 9220 3: a regular
 * `origin` header carries the browser client's origin for the server to
 * validate. Same borrow-or-scratch view as any other recovered line; other
 * regular fields stay ignored. */
static void take_origin(const rline* L, wired_h3reqdrive_req* r) {
  if (!line_name_is(L, "origin")) return;
  r->origin     = L->value;
  r->origin_len = L->value_len;
}

/* WebTransport draft-ietf-webtrans-http3-15 SS3.4: a regular
 * `wt-available-protocols` header carries the client's subprotocol offer (an
 * RFC 8941 sf-list of sf-strings). Copied verbatim into r's own fixed buffer
 * (unlike origin's borrowed view, see request_drive.h); a value that does not
 * fit is dropped, leaving the offer absent. */
static void take_wt_avail(const rline* L, wired_h3reqdrive_req* r) {
  if (!line_name_is(L, "wt-available-protocols")) return;
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
  if (line_name_is(L, "cookie")) cookie_join(r, L->value, L->value_len);
}

/* RFC 9110 10.1.1: a regular `expect` field carrying exactly "100-continue"
 * requests a 100 (Continue) interim response before the client sends the
 * message body. Mirrors line_name_is's own diff-accumulation shape (a single
 * loop, no per-byte branch) to stay at one branch total. */
static int value_is_100_continue(const rline* L) {
  static const u8 want[] = "100-continue";
  usz             n      = sizeof want - 1;
  u8              diff   = (u8)(L->value_len != n);
  for (usz i = 0; i < n && i < L->value_len; i++) diff |= L->value[i] ^ want[i];
  return diff == 0;
}

static void take_expect(const rline* L, wired_h3reqdrive_req* r) {
  if (line_name_is(L, "expect") && value_is_100_continue(L))
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
static void classify_line(const rline* L, wired_h3reqdrive_req* r) {
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

/* Cursor state shared by the field-line walkers below: the field section and
 * scratch buffer being walked, an offset into the section and how much
 * scratch has been consumed so far, plus the dynamic-table context (RFC 9204
 * 4.5.2/4.5.3) Indexed Field Lines resolve dynamic-table references against
 * -- dyn.table == 0 (no encoder stream seen yet) makes every dynamic
 * reference unresolvable, matching this decoder's prior static-only
 * behavior. */
typedef struct {
  wired_span  fs;
  wired_mspan scr;
  usz         off;
  usz         used;
  qdyn_src    dyn;
} rd_cursor;

/* RFC 9114 10.3, RFC 9110 5.5: neither half of a recovered field line may
 * carry a CR, LF or NUL octet -- such a line is malformed regardless of how
 * it was encoded. */
static int line_bytes_ok(const rline* L) {
  return h3_header_bytes_ok(L->name, L->name_len) &&
         h3_header_bytes_ok(L->value, L->value_len);
}

/* RFC 9114 4.1 / 4.2: request-smuggling defenses that key off the field
 * name -- Transfer-Encoding and the HTTP/1.1 connection-specific fields
 * (Connection, Keep-Alive, Proxy-Connection, Upgrade) are always malformed,
 * and a TE field's value must be exactly "trailers". */
static int line_smuggling_ok(const rline* L) {
  if (h3_header_name_forbidden(L->name, L->name_len)) return 0;
  if (!line_name_is(L, "te")) return 1;
  return h3_header_te_ok(L->value, L->value_len);
}

/* Decode failure or any malformed-line check on the recovered line. */
static int line_ok(const rline* L) {
  return line_bytes_ok(L) && line_smuggling_ok(L);
}

/* Decode one line at cur->off into r, advancing cur. Returns 1 ok, 0 on a
 * malformed line (decode failure or a forbidden CR/LF/NUL octet). */
static int step_line(rd_cursor* cur, wired_h3reqdrive_req* r) {
  rline      L;
  wired_span rest = wired_span_of(cur->fs.p + cur->off, cur->fs.n - cur->off);
  usz        c    = decode_line(
      rest, wired_mspan_of(cur->scr.p + cur->used, cur->scr.n - cur->used),
      &cur->dyn, &L);
  if (!c || !line_ok(&L)) return 0;
  classify_line(&L, r);
  cur->off += c;
  cur->used += L.scratch_used;
  return 1;
}

/* Walk field lines from cur->off to cur->fs.n into r. Returns 1 ok, 0 on a
 * malformed line. */
static int scan_lines(rd_cursor* cur, wired_h3reqdrive_req* r) {
  while (cur->off < cur->fs.n)
    if (!step_line(cur, r)) return 0;
  return 1;
}

/* RFC 9204 4.5.1.2 (9204-046): resolve the section prefix's Required Insert
 * Count and Base, rejecting a Sign=1 prefix whose Base would be negative
 * (qpack_base_valid). Returns bytes consumed by the prefix with *base
 * filled, 0 if the section prefix is malformed or names an invalid Base.
 * dyn is the table this section's dynamic references (if any) resolve
 * against; 0 (no encoder stream seen yet) still resolves a Base of 0
 * correctly since ric is 0 in that case (RFC 9204 4.5.1.1's EncodedInsertCount
 * 0 always decodes to RIC 0). */
/* The Required Insert Count context a section prefix's EncodedInsertCount
 * resolves against: dyn's own insertion count, or the empty-table default
 * (0) when dyn is 0 (no encoder stream seen yet). Split out of prefix_base
 * so its own branch count stays at the CCN gate. */
/* RFC 9204 3.2.2: MaxEntries is the dynamic table's capacity divided by 32. */
#define QPACK_DYN_ENTRY_SIZE_OVERHEAD 32

static qpack_ric_ctx dyn_ric_ctx(const qpack_dyn* dyn) {
  qpack_ric_ctx ctx = {0, 0};
  if (!dyn) return ctx;
  ctx.max_entries   = dyn->capacity / QPACK_DYN_ENTRY_SIZE_OVERHEAD;
  ctx.total_inserts = dyn->dropped + dyn->count;
  return ctx;
}

/* Resolve p's Required Insert Count and validate the Base it implies. Returns
 * 1 with *base filled, 0 if the EncodedInsertCount is invalid or the Base it
 * yields would be negative. Split out of prefix_base so its own branch count
 * stays at the CCN gate. */
static int prefix_resolve_base(
    const qpack_prefix* p, const qpack_dyn* dyn, u64* base) {
  qpack_ric_ctx ctx = dyn_ric_ctx(dyn);
  u64           ric;
  if (!qpack_ric_decode(p->required_insert_count, &ctx, &ric)) return 0;
  if (!qpack_base_valid(ric, p->sign, p->delta_base)) return 0;
  *base = qpack_base(ric, p->sign, p->delta_base);
  return 1;
}

static usz prefix_base(wired_span fs, const qpack_dyn* dyn, u64* base) {
  qpack_prefix p;
  usz          off = qpack_prefix_decode(fs.p, fs.n, &p);
  if (!off) return 0;
  return prefix_resolve_base(&p, dyn, base) ? off : 0;
}

/* RFC 9114 4.3.1: walk every field line after the section prefix in any order
 * or count, recovering the request pseudo-headers into r by name. dyn is the
 * connection's dynamic table (0 if none has been observed yet -- every
 * dynamic-table field-line reference then simply fails to resolve, see
 * line_indexed's own doc). */
static int decode_lines(
    wired_span            fs,
    wired_mspan           scr,
    const qpack_dyn*      dyn,
    wired_h3reqdrive_req* r) {
  rd_cursor cur = {fs, scr, 0, 0, {dyn, 0, fs}};
  cur.off       = prefix_base(fs, dyn, &cur.dyn.base);
  if (!cur.off) return 0;
  return scan_lines(&cur, r);
}

/* RFC 9114 4.3.1: a :path pseudo-header that was present (r->path != 0, so
 * CONNECT's legitimate omission is unaffected) but empty is malformed --
 * "*" (OPTIONS' asterisk-form, RFC 9114 4.3.1/9114-027) is one octet and
 * never trips this. */
static int path_present_and_empty(const wired_h3reqdrive_req* r) {
  return r->path != 0 && r->path_len == 0;
}

/* RFC 9114 4.1, RFC 9204 4.5 */
int wired_h3reqdrive_recv_get_dyn(
    wired_span            stream_data,
    wired_mspan           scratch,
    const qpack_dyn*      dyn,
    wired_h3reqdrive_req* r) {
  wired_span fs = wired_span_of(0, 0);
  *r            = (wired_h3reqdrive_req){0};
  h3_priority_init(&r->priority);
  if (!wired_h3reqdrive_request_sections(stream_data, &fs, r)) return 0;
  if (!decode_lines(fs, scratch, dyn, r)) return 0;
  return !path_present_and_empty(r);
}

/* RFC 9114 4.1, RFC 9204 4.5: static-table-only convenience wrapper (no
 * dynamic table observed / not tracked by this caller). */
int wired_h3reqdrive_recv_get(
    wired_span stream_data, wired_mspan scratch, wired_h3reqdrive_req* r) {
  return wired_h3reqdrive_recv_get_dyn(stream_data, scratch, 0, r);
}

/* 1 if the decoded line is well-formed AND carries no pseudo-header name
 * (RFC 9114 4.3: a trailer section has none at all -- unlike a leading field
 * section, where only ORDER after a regular field is the violation). Values
 * are discarded (a trailer's regular fields are unused by this SDK); only
 * the name classification and scratch bookkeeping matter here. */
static int trailer_line_ok(const rline* L) {
  return line_ok(L) && h3_ph_classify(L->name, L->name_len) == QUIC_H3_PH_NONE;
}

static int trailer_step_line(rd_cursor* cur) {
  rline L;
  usz   c = decode_line(
      wired_span_of(cur->fs.p + cur->off, cur->fs.n - cur->off),
      wired_mspan_of(cur->scr.p + cur->used, cur->scr.n - cur->used), &cur->dyn,
      &L);
  if (!c) return 0;
  if (!trailer_line_ok(&L)) return 0;
  cur->off += c;
  cur->used += L.scratch_used;
  return 1;
}

/* Walk every trailer field line, rejecting the section at the first
 * pseudo-header or malformed line. */
static int trailer_scan_lines(rd_cursor* cur) {
  while (cur->off < cur->fs.n)
    if (!trailer_step_line(cur)) return 0;
  return 1;
}

/* RFC 9114 4.3: a trailer section (if any) must carry no pseudo-header
 * fields. wired_h3reqdrive_request_trailer reports "no trailer present" as
 * 0, which this treats as vacuously ok -- most requests have no trailer.
 * @param stream_data the STREAM frame payload carrying the request
 * @param scratch caller-supplied scratch backing the trailer's literal
 *   values during the walk (discarded once this call returns)
 * @return 1 if there is no trailer, or the trailer has no pseudo-header and
 *   no malformed line; 0 if the trailer is malformed or carries one. */
int wired_h3reqdrive_trailer_ok(wired_span stream_data, wired_mspan scratch) {
  wired_span trailer_fs = wired_span_of(0, 0);
  rd_cursor  cur;
  if (!wired_h3reqdrive_request_trailer(stream_data, &trailer_fs)) return 1;
  cur.off = qpack_prefix_decode(trailer_fs.p, trailer_fs.n, &(qpack_prefix){0});
  if (!cur.off) return 0;
  cur.fs        = trailer_fs;
  cur.scr       = scratch;
  cur.used      = 0;
  cur.dyn.table = 0;
  cur.dyn.base  = 0;
  cur.dyn.fs    = trailer_fs;
  return trailer_scan_lines(&cur);
}
