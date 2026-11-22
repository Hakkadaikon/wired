#include "app/http3/request/h3reqdrive/request_drive_impl.h"

static int namref_name(
    wired_span fs, const qdyn_src* dyn, rline* L, wired_span* name);
static usz line_namref(
    wired_span fs, wired_mspan scr, const qdyn_src* dyn, rline* L);
static int postbase_name(
    wired_span fs, const qdyn_src* dyn, rline* L, wired_span* name);
static usz line_postbase(
    wired_span fs, wired_mspan scr, const qdyn_src* dyn, rline* L);
static usz line_litname(
    wired_span fs, wired_mspan scr, const qdyn_src* dyn, rline* L);

/* RFC 9204 4.5.4 / 2.2.3: a Literal With Name Reference's name -- the
 * static (T=1) or dynamic (T=0, relative to the Base) entry -- resolved
 * before its value is read, so an invalid reference is reported (ref_bad)
 * whatever the value holds. 1 with *name set. */
static int namref_name(
    wired_span fs, const qdyn_src* dyn, rline* L, wired_span* name) {
  qpack_nameref r   = {0, 0, 0};
  qdyn_src      src = {dyn->table, dyn->base, fs, dyn->ric};
  if (!qpack_literal_namref_head(fs, &r)) {
    return 0;
  }
  L->ref_bad = !qdyn_resolve_name(&src, r.is_static, r.index, name);
  return !L->ref_bad;
}

/* RFC 9204 4.5.4: a Literal With Name Reference -> the entry's name
 * (namref_name), copied value. */
static usz line_namref(
    wired_span fs, wired_mspan scr, const qdyn_src* dyn, rline* L) {
  qpack_nameref r  = {0, 0, 0};
  wired_obuf    vb = obuf_of(scr.p, scr.n);
  wired_span    name;
  usz           c;
  if (!namref_name(fs, dyn, L, &name)) {
    return 0;
  }
  c = qpack_literal_namref_decode(fs, &r, &vb);
  if (!c) {
    return 0;
  }
  h3reqdrive_literal_line(L, name, scr, vb.len);
  return c;
}

/* namref_name for the post-Base form: the dynamic entry past the Base. */
static int postbase_name(
    wired_span fs, const qdyn_src* dyn, rline* L, wired_span* name) {
  qpack_postbaseref r = {0, 0};
  if (!qpack_literal_postbase_head(fs, &r)) {
    return 0;
  }
  L->ref_bad = !qdyn_resolve_postbase_name(dyn, r.index, name);
  return !L->ref_bad;
}

/* RFC 9204 4.5.5: a Literal With Post-Base Name Reference -> the entry's
 * name (postbase_name), copied value. */
static usz line_postbase(
    wired_span fs, wired_mspan scr, const qdyn_src* dyn, rline* L) {
  qpack_postbaseref r  = {0, 0};
  wired_obuf        vb = obuf_of(scr.p, scr.n);
  wired_span        name;
  usz               c;
  if (!postbase_name(fs, dyn, L, &name)) {
    return 0;
  }
  c = qpack_literal_postbase_decode(fs, &r, &vb);
  if (!c) {
    return 0;
  }
  h3reqdrive_literal_line(L, name, scr, vb.len);
  return c;
}

/* RFC 9204 4.5.6: a Literal With Literal Name -> name at the scratch's
 * start, value right after it, so the line keeps only its own name + value
 * octets: a section within the advertised SETTINGS_MAX_FIELD_SECTION_SIZE
 * (which accounts 32 more per line, RFC 9114 4.2.2) always fits a scratch
 * of that size, whatever the name's length (RFC 9110 5.1 sets none). */
static usz line_litname(
    wired_span fs, wired_mspan scr, const qdyn_src* dyn, rline* L) {
  wired_obuf nm  = obuf_of(scr.p, scr.n);
  usz        off = qpack_literal_name_head(fs, &nm);
  wired_obuf vb;
  usz        w;
  (void)dyn;
  if (!off) {
    return 0;
  }
  vb = obuf_of(scr.p + nm.len, scr.n - nm.len);
  w  = qpack_string_decode(wired_span_of(fs.p + off, fs.n - off), &vb);
  if (!w) {
    return 0;
  }
  L->name         = scr.p;
  L->name_len     = nm.len;
  L->value        = scr.p + nm.len;
  L->value_len    = vb.len;
  L->scratch_used = nm.len + vb.len;
  return off + w;
}

/* RFC 9204 4.5: the five field line forms, tried in turn; each rejects a
 * pattern that is not its own. */
usz (*const line_forms[])(wired_span, wired_mspan, const qdyn_src*, rline*) = {
    h3reqdrive_line_indexed, line_namref, line_postbase, line_litname};
