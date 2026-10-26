#include "app/http3/request/h3reqdrive/request_drive_impl.h"

static qpack_ric_ctx dyn_ric_ctx(const qpack_dyn* dyn);
static int           prefix_ric_ok(
    const qpack_prefix* p, u64 ric, const qpack_ric_ctx* c);
static int prefix_resolve_base(
    const qpack_prefix* p, const qpack_dyn* dyn, u64* base, u64* ric);
static int decode_lines(
    wired_span            fs,
    wired_mspan           scr,
    const qpack_dyn*      dyn,
    wired_h3reqdrive_req* r,
    usz*                  used);
static int trailer_line_ok(const rline* L);
static int trailer_step_line(rd_cursor* cur, wired_h3reqdrive_req* r);
static int trailer_scan_lines(rd_cursor* cur, wired_h3reqdrive_req* r);
static int trailer_decode(
    wired_span            stream_data,
    wired_mspan           scr,
    const qpack_dyn*      dyn,
    wired_h3reqdrive_req* r);

static qpack_ric_ctx dyn_ric_ctx(const qpack_dyn* dyn) {
  qpack_ric_ctx ctx = {0, 0};
  if (!dyn) {
    return ctx;
  }
  ctx.max_entries   = dyn->max_capacity / QPACK_DYN_ENTRY_SIZE_OVERHEAD;
  ctx.total_inserts = dyn->dropped + dyn->count;
  return ctx;
}

/* RFC 9204 4.5.1.2 / 2.1.2: the Base is non-negative, and -- no stream may
 * block (SETTINGS_QPACK_BLOCKED_STREAMS 0) -- the Required Insert Count is
 * no more than the inserts already received. */
static int prefix_ric_ok(
    const qpack_prefix* p, u64 ric, const qpack_ric_ctx* c) {
  return qpack_base_valid(ric, p->sign, p->delta_base) &&
         ric <= c->total_inserts;
}

/* Resolve p's Required Insert Count and validate the Base it implies. Returns
 * 1 with *base and *ric filled, 0 if the EncodedInsertCount is invalid or
 * prefix_ric_ok rejects it. Split out of h3reqdrive_prefix_base so its own
 * branch count stays at the CCN gate. */
static int prefix_resolve_base(
    const qpack_prefix* p, const qpack_dyn* dyn, u64* base, u64* ric) {
  qpack_ric_ctx ctx = dyn_ric_ctx(dyn);
  if (!qpack_ric_decode(p->required_insert_count, &ctx, ric)) {
    return 0;
  }
  if (!prefix_ric_ok(p, *ric, &ctx)) {
    return 0;
  }
  *base = qpack_base(*ric, p->sign, p->delta_base);
  return 1;
}

usz h3reqdrive_prefix_base(
    wired_span fs, const qpack_dyn* dyn, u64* base, u64* ric) {
  qpack_prefix p;
  usz          off = qpack_prefix_decode(fs.p, fs.n, &p);
  if (!off) {
    return 0;
  }
  return prefix_resolve_base(&p, dyn, base, ric) ? off : 0;
}

/* RFC 9114 4.3 / 4.3.1: walk every field line after the section prefix,
 * recovering the request pseudo-headers into r by name, then require the
 * pseudo-header set and order a request must carry (h3reqdrive_ph_ok). dyn is
 * the connection's dynamic table (0 if none has been observed yet -- every
 * dynamic-table field-line reference then simply fails to resolve, see
 * h3reqdrive_line_indexed's own doc). */
static int decode_lines(
    wired_span            fs,
    wired_mspan           scr,
    const qpack_dyn*      dyn,
    wired_h3reqdrive_req* r,
    usz*                  used) {
  rd_cursor cur = {fs, scr, 0, 0, {dyn, 0, fs, 0}, {0, 0, 0}};
  int       ok  = 0;
  h3_ph_init(&cur.ph);
  cur.off      = h3reqdrive_prefix_base(fs, dyn, &cur.dyn.base, &cur.dyn.ric);
  r->qpack_ric = cur.dyn.ric;
  r->qpack_failed = cur.off == 0;
  if (cur.off) {
    ok = h3reqdrive_scan_lines(&cur, r) && h3reqdrive_ph_ok(&cur.ph, r);
  }
  *used = cur.used;
  return ok;
}

/* 1 if the decoded line is well-formed AND carries no pseudo-header name
 * (RFC 9114 4.3: a trailer section has none at all -- unlike a leading field
 * section, where only ORDER after a regular field is the violation). Values
 * are discarded (a trailer's regular fields are unused by this SDK); only
 * the name classification and scratch bookkeeping matter here. */
static int trailer_line_ok(const rline* L) {
  return h3reqdrive_line_ok(L) &&
         h3_ph_classify(L->name, L->name_len) == H3_PH_NONE;
}

static int trailer_step_line(rd_cursor* cur, wired_h3reqdrive_req* r) {
  rline L = {0};
  usz   c = h3reqdrive_decode_line(
      wired_span_of(cur->fs.p + cur->off, cur->fs.n - cur->off),
      wired_mspan_of(cur->scr.p + cur->used, cur->scr.n - cur->used), &cur->dyn,
      &L);
  r->qpack_failed = L.ref_bad; /* RFC 9204 2.2.3, as in h3reqdrive_step_line */
  if (!c) {
    r->reject_code = QPACK_DECOMPRESSION_FAILED; /* RFC 9204 7.4 */
    return 0;
  }
  if (!trailer_line_ok(&L)) {
    return 0;
  }
  cur->off += c;
  cur->used += L.scratch_used;
  return 1;
}

/* Walk every trailer field line, rejecting the section at the first
 * pseudo-header or malformed line. */
static int trailer_scan_lines(rd_cursor* cur, wired_h3reqdrive_req* r) {
  while (cur->off < cur->fs.n) {
    if (!trailer_step_line(cur, r)) {
      return 0;
    }
  }
  return 1;
}

/* RFC 9114 4.3 / RFC 9204 2.2.2.1: decode the trailer section (if any)
 * against dyn into r's qpack_trailer_ric/qpack_failed, its values only in
 * scr. 1 if there is none or it is well-formed with no pseudo-header. */
static int trailer_decode(
    wired_span            stream_data,
    wired_mspan           scr,
    const qpack_dyn*      dyn,
    wired_h3reqdrive_req* r) {
  wired_span tfs = wired_span_of(0, 0);
  rd_cursor  cur;
  if (!wired_h3reqdrive_request_trailer(stream_data, &tfs)) {
    return 1;
  }
  cur     = (rd_cursor){tfs, scr, 0, 0, {dyn, 0, tfs, 0}, {0, 0, 0}};
  cur.off = h3reqdrive_prefix_base(tfs, dyn, &cur.dyn.base, &cur.dyn.ric);
  r->qpack_trailer_ric = cur.dyn.ric;
  r->qpack_failed      = cur.off == 0;
  if (!cur.off) {
    return 0;
  }
  return trailer_scan_lines(&cur, r);
}

/* The leading field section, then the trailer section (if any) in the
 * scratch the leading one left free. */
int h3reqdrive_decode_sections(
    wired_span            stream_data,
    wired_span            fs,
    wired_mspan           scr,
    const qpack_dyn*      dyn,
    wired_h3reqdrive_req* r) {
  usz used = 0;
  if (!decode_lines(fs, scr, dyn, r, &used)) {
    return 0;
  }
  return trailer_decode(
      stream_data, wired_mspan_of(scr.p + used, scr.n - used), dyn, r);
}
