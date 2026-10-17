#include "app/http3/request/h3reqdrive/request_drive_impl.h"

static int namref_name(
    wired_span fs, const qdyn_src* dyn, rline* L, wired_span* name);
static usz line_namref(
    wired_span fs, wired_mspan scr, const qdyn_src* dyn, rline* L);
static int postbase_name(
    wired_span fs, const qdyn_src* dyn, rline* L, wired_span* name);
static usz line_postbase(
    wired_span fs, wired_mspan scr, const qdyn_src* dyn, rline* L);
static usz litname_split(usz scr_n);
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

static usz litname_split(usz scr_n) {
  return scr_n > LITNAME_NAME_CAP ? LITNAME_NAME_CAP : scr_n / 2;
}

/* RFC 9204 4.5.6: a Literal With Literal Name -> name in the first (capped)
 * scratch share, value in the rest (disjoint, both written in one call). */
static usz line_litname(
    wired_span fs, wired_mspan scr, const qdyn_src* dyn, rline* L) {
  int never = 0;
  (void)dyn;
  usz            half = litname_split(scr.n);
  qpack_fieldbuf fb   = {
      obuf_of(scr.p, half), obuf_of(scr.p + half, scr.n - half)};
  usz c = qpack_literal_name_decode(fs, &never, &fb);
  if (!c) {
    return 0;
  }
  L->name         = scr.p;
  L->name_len     = fb.name.len;
  L->value        = scr.p + half;
  L->value_len    = fb.value.len;
  L->scratch_used = half + fb.value.len;
  return c;
}

/* RFC 9204 4.5: the five field line forms, tried in turn; each rejects a
 * pattern that is not its own. */
usz (*const line_forms[])(wired_span, wired_mspan, const qdyn_src*, rline*) = {
    h3reqdrive_line_indexed, line_namref, line_postbase, line_litname};
