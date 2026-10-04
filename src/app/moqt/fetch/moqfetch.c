#include "app/moqt/fetch/moqfetch.h"

#include "app/moqt/data/moqdata.h"
#include "app/moqt/vi/moqvi.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"

/* Every helper returns MOQCTL_OK / INSUFFICIENT / VIOLATION (takes) or
 * 1 / 0 (puts); multi-field layouts run as step tables so no function
 * chains more than two fallible calls (CCN <= 3). */

/* ===== FETCH (draft-ietf-moq-transport-19 10.12) ===== */

/* 10.12.1: Track Namespace, Track Name, Start Location, End Location. */
static int moqfetch_take_range(wired_span b, usz* at, moqfetch_fetch* m) {
  int r = moqctl_loc_take(b, at, &m->start);
  if (r != MOQCTL_OK) return r;
  return moqctl_loc_take(b, at, &m->end);
}

static int moqfetch_take_standalone(wired_span b, usz* at, moqfetch_fetch* m) {
  int r = moqctl_ftn_take(b, at, &m->track);
  if (r != MOQCTL_OK) return r;
  return moqfetch_take_range(b, at, m);
}

/* 10.12.2: Joining Request ID, Joining Start. */
static int moqfetch_take_joining(wired_span b, usz* at, moqfetch_fetch* m) {
  if (!moqvi_take(b, at, &m->joining_request_id)) return MOQCTL_INSUFFICIENT;
  if (!moqvi_take(b, at, &m->joining_start)) return MOQCTL_INSUFFICIENT;
  return MOQCTL_OK;
}

/* 10.12: "a Fetch Type other than 0x1, 0x2 or 0x3 MUST close the session
 * with a PROTOCOL_VIOLATION". */
static int moqfetch_take_badtype(wired_span b, usz* at, moqfetch_fetch* m) {
  (void)b, (void)at, (void)m;
  return MOQCTL_VIOLATION;
}

typedef int (*moqfetch_variant_take_fn)(wired_span, usz*, moqfetch_fetch*);
static const moqfetch_variant_take_fn MOQFETCH_VARIANT_TAKE[4] = {
    moqfetch_take_badtype, moqfetch_take_standalone, moqfetch_take_joining,
    moqfetch_take_joining};

/* Table index of a Fetch Type: 1..3, or 0 for any invalid value. */
static usz moqfetch_variant(u64 fetch_type) {
  return fetch_type <= MOQFETCH_ABSOLUTE_JOINING ? (usz)fetch_type : 0;
}

static int moqfetch_take_head(wired_span b, usz* at, moqfetch_fetch* m) {
  if (!moqvi_take(b, at, &m->request_id)) return MOQCTL_INSUFFICIENT;
  if (!moqvi_take(b, at, &m->fetch_type)) return MOQCTL_INSUFFICIENT;
  return MOQFETCH_VARIANT_TAKE[moqfetch_variant(m->fetch_type)](b, at, m);
}

int moqfetch_fetch_take(int ver, wired_span body, moqfetch_fetch* out) {
  usz at = 0;
  int r  = moqfetch_take_head(body, &at, out);
  if (r == MOQCTL_OK)
    r = moqctl_params_take(ver, body, &at, MOQCTL_PCTX_FETCH, &out->params);
  return moqctl_body_end(r, at, body);
}

static int moqfetch_put_standalone(
    wired_mspan b, usz* at, const moqfetch_fetch* m) {
  if (!moqctl_ftn_put(b, at, &m->track)) return 0;
  if (!moqctl_loc_put(b, at, m->start)) return 0;
  return moqctl_loc_put(b, at, m->end);
}

static int moqfetch_put_joining(
    wired_mspan b, usz* at, const moqfetch_fetch* m) {
  if (!moqvi_put(b, at, m->joining_request_id)) return 0;
  return moqvi_put(b, at, m->joining_start);
}

static int moqfetch_put_badtype(
    wired_mspan b, usz* at, const moqfetch_fetch* m) {
  (void)b, (void)at, (void)m;
  return 0;
}

typedef int (*moqfetch_variant_put_fn)(
    wired_mspan, usz*, const moqfetch_fetch*);
static const moqfetch_variant_put_fn MOQFETCH_VARIANT_PUT[4] = {
    moqfetch_put_badtype, moqfetch_put_standalone, moqfetch_put_joining,
    moqfetch_put_joining};

static int moqfetch_put_head(wired_mspan b, usz* at, const moqfetch_fetch* m) {
  if (!moqvi_put(b, at, m->request_id)) return 0;
  return moqvi_put(b, at, m->fetch_type);
}

int moqfetch_fetch_encode(wired_mspan buf, usz* off, const moqfetch_fetch* m) {
  if (!moqfetch_put_head(buf, off, m)) return 0;
  if (!MOQFETCH_VARIANT_PUT[moqfetch_variant(m->fetch_type)](buf, off, m))
    return 0;
  return moqctl_params_put(buf, off, &m->params);
}

/* ===== moqfetch_req: version-neutral FETCH (19 SS10.12, 22 SS9.11) =====
 * A thin translation layer over moqfetch_fetch (d19 wire) / moqctl_rangeloc
 * (d19 Standalone Start/End <-> d22 LOCATION_FILTER), not a reimplementation
 * of either wire parser. */

/* 10.12.1: "End Location: the end Location, plus 1. A Location.Object value
 * of 0 means the entire group is requested." The inclusive end
 * (moqfetch_end19_incl) is a whole group (MOQCTL_REK_GROUP) when its Object
 * is MOQFETCH_OBJ_GROUP_END, else {end_group, end_object} (MOQCTL_REK_OBJ). */
static void moqfetch_req_range_from_end(moqctl_loc end, moqctl_rangeloc* r) {
  moqctl_loc e  = moqfetch_end19_incl(end);
  r->end_group  = e.group;
  r->end_object = e.object;
  r->ek =
      e.object == MOQFETCH_OBJ_GROUP_END ? MOQCTL_REK_GROUP : MOQCTL_REK_OBJ;
}

static void moqfetch_req_standalone_from(
    const moqfetch_fetch* f, moqfetch_req* out) {
  out->track              = f->track;
  out->range.sk           = MOQCTL_RSK_ABS;
  out->range.start_group  = f->start.group;
  out->range.start_object = f->start.object;
  moqfetch_req_range_from_end(f->end, &out->range);
}

static void moqfetch_req_from_fetch(
    const moqfetch_fetch* f, moqfetch_req* out) {
  out->request_id = f->request_id;
  out->fetch_type = f->fetch_type;
  out->params     = f->params;
  out->is_joining = f->fetch_type != MOQFETCH_STANDALONE;
  if (out->is_joining) {
    out->joining_request_id = f->joining_request_id;
    out->joining_start      = f->joining_start;
    return;
  }
  moqfetch_req_standalone_from(f, out);
}

int moqfetch_req19_take(int ver, wired_span body, moqfetch_req* out) {
  moqfetch_fetch f;
  int            r = moqfetch_fetch_take(ver, body, &f);
  if (r != MOQCTL_OK) return r;
  *out = (moqfetch_req){0};
  moqfetch_req_from_fetch(&f, out);
  return MOQCTL_OK;
}

/* Inverse of moqfetch_req_range_from_end. */
static moqctl_loc moqfetch_req_end_to_loc(const moqctl_rangeloc* r) {
  moqctl_loc e = moqctl_loc_of(r->end_group, r->end_object);
  return moqfetch_end19_wire(moqfetch_req_end(r, e));
}

static void moqfetch_req_to_fetch(const moqfetch_req* m, moqfetch_fetch* f) {
  f->request_id = m->request_id;
  f->fetch_type = m->fetch_type;
  f->params     = m->params;
  if (m->is_joining) {
    f->joining_request_id = m->joining_request_id;
    f->joining_start      = m->joining_start;
    return;
  }
  f->track = m->track;
  f->start = moqctl_loc_of(m->range.start_group, m->range.start_object);
  f->end   = moqfetch_req_end_to_loc(&m->range);
}

int moqfetch_req19_encode(wired_mspan buf, usz* off, const moqfetch_req* m) {
  moqfetch_fetch f = {0};
  moqfetch_req_to_fetch(m, &f);
  return moqfetch_fetch_encode(buf, off, &f);
}

/* draft-22 FETCH body: Request ID, Track Namespace, Track Name, Parameters
 * (draft-22 parameters, so LOCATION_FILTER decodes per SS9.20.9, not d19's
 * Length-prefixed SS5.1.2 shape). */
static int moqfetch_req22_take_head(wired_span b, usz* at, moqfetch_req* m) {
  int r;
  if (!moqvi_take(b, at, &m->request_id)) return MOQCTL_INSUFFICIENT;
  r = moqctl_ns_take(b, at, &m->track.ns);
  if (r != MOQCTL_OK) return r;
  return moqctl_name_take(b, at, &m->track.name);
}

/* SS9.20.9: "If omitted from FETCH ..., the fetch ... is unfiltered" ->
 * the whole track (sk=ABS, start {0,0}, ek=UNBOUNDED), not a rejection. */
static void moqfetch_req22_range_default(moqctl_rangeloc* r) {
  *r    = (moqctl_rangeloc){0};
  r->sk = MOQCTL_RSK_ABS;
  r->ek = MOQCTL_REK_UNBOUNDED;
}

static void moqfetch_req22_range_from_params(moqfetch_req* m) {
  const moqctl_param* p =
      moqctl_params_find(&m->params, MOQCTL_PARAM_LOCATION_FILTER);
  if (!p || !p->has_filter) {
    moqfetch_req22_range_default(&m->range);
    return;
  }
  m->range = p->rl;
}

int moqfetch_req22_take(wired_span body, moqfetch_req* out) {
  usz at = 0;
  int r  = moqfetch_req22_take_head(body, &at, out);
  if (r == MOQCTL_OK)
    r = moqctl_params_take(
        MOQVER_D22, body, &at, MOQCTL_PCTX_FETCH, &out->params);
  r = moqctl_body_end(r, at, body);
  if (r != MOQCTL_OK) return r;
  out->is_joining = 0;
  out->fetch_type = MOQFETCH_STANDALONE;
  moqfetch_req22_range_from_params(out);
  return MOQCTL_OK;
}

/* Re-derives the LOCATION_FILTER parameter from m->range (always present
 * on encode: the "fetch everything" default and an explicit filter use the
 * same moqctl_rangeloc22_put(has_filter=1, ...) shape as any other
 * absolute-start/open-ended filter -- a receiver cannot tell them apart on
 * the wire, nor needs to). */
static usz moqfetch_req22_filter_slot(const moqctl_params* params) {
  usz i;
  for (i = 0; i < params->n; i++) {
    if (params->items[i].type >= MOQCTL_PARAM_LOCATION_FILTER) break;
  }
  return i;
}

/* moqctl_params_put writes items[] in order under a strict-ascending-type
 * check (it does not sort), so the synthesized filter must be inserted at
 * the position that keeps type order, not appended after possibly-larger
 * existing types (e.g. GROUP_ORDER 0x22 > LOCATION_FILTER 0x21). */
static void moqfetch_req22_put_filter(moqfetch_req* m) {
  moqctl_param* p;
  usz           slot, j;
  if (moqctl_params_find(&m->params, MOQCTL_PARAM_LOCATION_FILTER)) return;
  slot = moqfetch_req22_filter_slot(&m->params);
  for (j = m->params.n; j > slot; j--)
    m->params.items[j] = m->params.items[j - 1];
  p             = &m->params.items[slot];
  p->type       = MOQCTL_PARAM_LOCATION_FILTER;
  p->enc        = MOQCTL_PENC_RANGELOC22;
  p->has_filter = 1;
  p->rl         = m->range;
  m->params.n++;
}

static int moqfetch_req22_put_head(
    wired_mspan buf, usz* off, const moqfetch_req* m) {
  if (!moqvi_put(buf, off, m->request_id)) return 0;
  return moqctl_ns_put(buf, off, &m->track.ns);
}

int moqfetch_req22_encode(wired_mspan buf, usz* off, const moqfetch_req* m) {
  moqfetch_req tmp = *m;
  moqfetch_req22_put_filter(&tmp);
  if (!moqfetch_req22_put_head(buf, off, &tmp)) return 0;
  if (!moqctl_name_put(buf, off, tmp.track.name)) return 0;
  return moqctl_params_put(buf, off, &tmp.params);
}

/* ===== FILL_PARAMETERS value (draft-22 SS9.20.15) ===== */

/* The Parameters must fill the value exactly (its Length already framed
 * it). */
static int moqfetch_fill_params(wired_span v, moqctl_params* p) {
  usz at = 0;
  int r  = moqctl_params_take(MOQVER_D22, v, &at, MOQCTL_PCTX_FETCH, p);
  if (r != MOQCTL_OK) return r;
  return at == v.n ? MOQCTL_OK : MOQCTL_VIOLATION;
}

/* LOCATION_FILTER type 0x00 decodes as has_filter 0 (SS9.20.9 None); an
 * absent parameter reads the same. */
static void moqfetch_fill_filter_of(const moqctl_params* p, moqfetch_fill* o) {
  const moqctl_param* lf = moqctl_params_find(p, MOQCTL_PARAM_LOCATION_FILTER);
  if (!lf || !lf->has_filter) return;
  o->has_filter = 1;
  o->range      = lf->rl;
}

static int moqfetch_fill_desc_of(const moqctl_params* p) {
  const moqctl_param* go = moqctl_params_find(p, MOQCTL_PARAM_GROUP_ORDER);
  return go != 0 && go->u8v == 2;
}

static void moqfetch_fill_tmo_of(const moqctl_params* p, moqfetch_fill* o) {
  const moqctl_param* to = moqctl_params_find(p, MOQCTL_PARAM_FILL_TIMEOUT);
  o->has_timeout         = to != 0;
  if (to) o->timeout_ms = to->vi;
}

int moqfetch_fill_take(wired_span value, moqfetch_fill* out) {
  moqctl_params p;
  p.n = 0; /* a zero-length value is "no parameters" */
  bytes_memset(out, 0, sizeof *out);
  if (value.n != 0) {
    int r = moqfetch_fill_params(value, &p);
    if (r != MOQCTL_OK) return r;
  }
  moqfetch_fill_filter_of(&p, out);
  out->descending = moqfetch_fill_desc_of(&p);
  moqfetch_fill_tmo_of(&p, out);
  return MOQCTL_OK;
}

/* Items in ascending Type order (moqctl_params_put encodes deltas):
 * FILL_TIMEOUT 0x0A, LOCATION_FILTER 0x21 (always present -- a fill
 * without a filter sends type 0x00), GROUP_ORDER 0x22. */
static usz moqfetch_fill_items(const moqfetch_fill* f, moqctl_params* p) {
  usz n = 0;
  if (f->has_timeout) {
    p->items[n].type = MOQCTL_PARAM_FILL_TIMEOUT;
    p->items[n].enc  = MOQCTL_PENC_VARINT;
    p->items[n].vi   = f->timeout_ms;
    n++;
  }
  p->items[n].type       = MOQCTL_PARAM_LOCATION_FILTER;
  p->items[n].enc        = MOQCTL_PENC_RANGELOC22;
  p->items[n].has_filter = f->has_filter;
  p->items[n].rl         = f->range;
  n++;
  if (f->descending) {
    p->items[n].type = MOQCTL_PARAM_GROUP_ORDER;
    p->items[n].enc  = MOQCTL_PENC_UINT8;
    p->items[n].u8v  = 2;
    n++;
  }
  return n;
}

int moqfetch_fill_put(wired_mspan buf, usz* off, const moqfetch_fill* f) {
  moqctl_params p = {0};
  p.n             = moqfetch_fill_items(f, &p);
  return moqctl_params_put(buf, off, &p);
}

/* ===== FETCH_OK (10.13 Figure 16) ===== */

static int moqfetch_ok_take_head(wired_span b, usz* at, moqfetch_ok* m) {
  int r = moqctl_param_take_uint8(b, at, &m->end_of_track);
  if (r != MOQCTL_OK) return r;
  return moqctl_loc_take(b, at, &m->end);
}

int moqfetch_ok_take(int ver, wired_span body, moqfetch_ok* out) {
  usz at = 0;
  int r  = moqfetch_ok_take_head(body, &at, out);
  if (r == MOQCTL_OK)
    r = moqctl_params_take(ver, body, &at, MOQCTL_PCTX_FETCH_OK, &out->params);
  out->track_properties = wired_span_of(body.p + at, body.n - at);
  return moqctl_body_end(r, body.n, body);
}

static int moqfetch_ok_put_head(wired_mspan b, usz* at, const moqfetch_ok* m) {
  if (!moqctl_param_put_uint8(b, at, m->end_of_track)) return 0;
  return moqctl_loc_put(b, at, m->end);
}

int moqfetch_ok_encode(wired_mspan buf, usz* off, const moqfetch_ok* m) {
  if (!moqfetch_ok_put_head(buf, off, m)) return 0;
  if (!moqctl_params_put(buf, off, &m->params)) return 0;
  return bytes_put(buf, off, m->track_properties);
}

moqctl_loc moqfetch_end19_incl(moqctl_loc wire) {
  return moqctl_loc_of(wire.group, wire.object - 1); /* 0 - 1 = GROUP_END */
}

moqctl_loc moqfetch_end19_wire(moqctl_loc incl) {
  return moqctl_loc_of(incl.group, incl.object + 1); /* GROUP_END + 1 = 0 */
}

moqctl_loc moqfetch_req_end(const moqctl_rangeloc* r, moqctl_loc largest) {
  if (r->ek == MOQCTL_REK_UNBOUNDED) return largest;
  if (r->ek == MOQCTL_REK_GROUP)
    return moqctl_loc_of(r->end_group, MOQFETCH_OBJ_GROUP_END);
  return moqctl_loc_of(r->end_group, r->end_object);
}

int moqfetch_ok19_encode(wired_mspan buf, usz* off, const moqfetch_ok* m) {
  moqfetch_ok w = *m;
  w.end         = moqfetch_end19_wire(m->end);
  return moqfetch_ok_encode(buf, off, &w);
}

/* ===== FETCH_HEADER (11.4.4 Figure 26) ===== */

static int moqfetch_hdr_type(wired_span buf, usz* at) {
  u64 type;
  if (!moqvi_take(buf, at, &type)) return MOQCTL_INSUFFICIENT;
  return type == MOQDATA_TYPE_FETCH_HEADER ? MOQCTL_OK : MOQCTL_VIOLATION;
}

int moqfetch_hdr_take(wired_span buf, usz* off, u64* request_id) {
  usz at = *off;
  int r  = moqfetch_hdr_type(buf, &at);
  if (r != MOQCTL_OK) return r;
  if (!moqvi_take(buf, &at, request_id)) return MOQCTL_INSUFFICIENT;
  *off = at;
  return MOQCTL_OK;
}

int moqfetch_hdr_put(wired_mspan buf, usz* off, u64 request_id) {
  if (!moqvi_put(buf, off, MOQDATA_TYPE_FETCH_HEADER)) return 0;
  return moqvi_put(buf, off, request_id);
}

/* ===== Fetch Objects (11.4.4 Figure 27, 11.4.4.1, 11.4.4.2) ===== */

/* a + b, or VIOLATION past 2^64-1 (11.4.4.1). */
static int moqfetch_add(u64 a, u64 b, u64* out) {
  return u64_add_ok(a, b, out) ? MOQCTL_OK : MOQCTL_VIOLATION;
}

/* Ascending: prior + (Delta + 1). */
static int moqfetch_group_up(u64 prior, u64 d, u64* out) {
  u64 step;
  if (moqfetch_add(d, 1, &step) != MOQCTL_OK) return MOQCTL_VIOLATION;
  return moqfetch_add(prior, step, out);
}

/* Descending: prior - (Delta + 1), a VIOLATION below 0. */
static int moqfetch_group_down(u64 prior, u64 d, u64* out) {
  if (d >= prior) return MOQCTL_VIOLATION;
  *out = prior - d - 1;
  return MOQCTL_OK;
}

/* "The first Object MUST include a Group ID Delta and Object ID Delta, and
 * these values are the absolute Group ID and Object ID." */
static int moqfetch_group_resolve(const moqfetch_seq* s, u64 d, u64* g) {
  if (!s->have_loc) {
    *g = d;
    return MOQCTL_OK;
  }
  return s->descending ? moqfetch_group_down(s->group, d, g)
                       : moqfetch_group_up(s->group, d, g);
}

typedef int (*moqfetch_step_fn)(
    wired_span, usz*, const moqfetch_seq*, moqfetch_obj*);

static int moqfetch_first_ok(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)b, (void)at;
  if (s->have_loc) return MOQCTL_OK;
  return (o->flags & (MOQFETCH_F_GROUP | MOQFETCH_F_OBJECT)) ==
                 (MOQFETCH_F_GROUP | MOQFETCH_F_OBJECT)
             ? MOQCTL_OK
             : MOQCTL_VIOLATION;
}

/* Absent Group ID Delta: the prior Object's Group ID. */
static int moqfetch_take_group(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  u64 d;
  o->group = s->group;
  if (!(o->flags & MOQFETCH_F_GROUP)) return MOQCTL_OK;
  if (!moqvi_take(b, at, &d)) return MOQCTL_INSUFFICIENT;
  return moqfetch_group_resolve(s, d, &o->group);
}

/* 11.4.4.1 Table 8: Subgroup 0 / prior / prior + 1 / explicit field.
 * Referencing a prior Subgroup that does not exist is a VIOLATION
 * (11.4.4.1 first Object, 11.4.4.2 after End of Range). */
static int moqfetch_sg_zero(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)b, (void)at, (void)s;
  o->subgroup = 0;
  return MOQCTL_OK;
}

static int moqfetch_sg_prior(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)b, (void)at;
  if (!s->have_subgroup) return MOQCTL_VIOLATION;
  o->subgroup = s->subgroup;
  return MOQCTL_OK;
}

static int moqfetch_sg_next(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)b, (void)at;
  if (!s->have_subgroup) return MOQCTL_VIOLATION;
  return moqfetch_add(s->subgroup, 1, &o->subgroup);
}

static int moqfetch_sg_field(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)s;
  return moqvi_take(b, at, &o->subgroup) ? MOQCTL_OK : MOQCTL_INSUFFICIENT;
}

static const moqfetch_step_fn MOQFETCH_SG_TAKE[4] = {
    moqfetch_sg_zero, moqfetch_sg_prior, moqfetch_sg_next, moqfetch_sg_field};

/* 0x40: a Datagram-preference Object has no Subgroup ID; the two LSBs are
 * ignored. */
static int moqfetch_take_subgroup(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  o->subgroup     = 0;
  o->has_subgroup = !(o->flags & MOQFETCH_F_DATAGRAM);
  if (!o->has_subgroup) return MOQCTL_OK;
  return MOQFETCH_SG_TAKE[o->flags & MOQFETCH_F_SUBGROUP_MASK](b, at, s, o);
}

/* With a Group ID Delta (or on the first Object) the Object ID Delta is
 * the absolute Object ID; otherwise it is added to the prior one. */
static int moqfetch_object_absolute(
    const moqfetch_seq* s, const moqfetch_obj* o) {
  return (o->flags & MOQFETCH_F_GROUP) || !s->have_loc;
}

static int moqfetch_object_resolve(
    const moqfetch_seq* s, moqfetch_obj* o, u64 d) {
  o->object = d;
  if (moqfetch_object_absolute(s, o)) return MOQCTL_OK;
  return moqfetch_add(s->object, d, &o->object);
}

/* Absent Object ID Delta: the prior Object ID + 1, whatever the group. */
static int moqfetch_take_object(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  u64 d;
  if (!(o->flags & MOQFETCH_F_OBJECT))
    return moqfetch_add(s->object, 1, &o->object);
  if (!moqvi_take(b, at, &d)) return MOQCTL_INSUFFICIENT;
  return moqfetch_object_resolve(s, o, d);
}

static int moqfetch_take_priority(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  if (o->flags & MOQFETCH_F_PRIORITY)
    return moqctl_param_take_uint8(b, at, &o->priority);
  if (!s->have_priority) return MOQCTL_VIOLATION;
  o->priority = s->priority;
  return MOQCTL_OK;
}

/* Object Properties (11.2.1.2): Properties Length + KVP bytes. */
static int moqfetch_take_props(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)s;
  o->props     = wired_span_of(b.p, 0);
  o->has_props = (o->flags & MOQFETCH_F_PROPS) != 0;
  if (!o->has_props) return MOQCTL_OK;
  return moqctl_name_take(b, at, &o->props);
}

static int moqfetch_take_payload(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)s;
  return moqctl_name_take(b, at, &o->payload);
}

/* 11.4.4.2: "the Group ID and Object ID fields are present. Subgroup ID,
 * Priority and Properties are not present." They are the absolute
 * Location ending the range (a delta could not name a Location inside the
 * prior Object's Group), and no Object Payload Length follows. */
static int moqfetch_take_eor(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)s;
  if (!moqvi_take(b, at, &o->group)) return MOQCTL_INSUFFICIENT;
  return moqvi_take(b, at, &o->object) ? MOQCTL_OK : MOQCTL_INSUFFICIENT;
}

/* Wire order of Figure 27. */
static const moqfetch_step_fn MOQFETCH_OBJ_STEPS[] = {
    moqfetch_first_ok,     moqfetch_take_group,    moqfetch_take_subgroup,
    moqfetch_take_object,  moqfetch_take_priority, moqfetch_take_props,
    moqfetch_take_payload,
};
static const moqfetch_step_fn MOQFETCH_EOR_STEPS[] = {moqfetch_take_eor};

#define MOQFETCH_N(a) (sizeof(a) / sizeof((a)[0]))

/* "Prior Group ID and prior Object ID: The values from the End of Range
 * indicator"; Subgroup and Priority stay those of the last real Object. */
static void moqfetch_note_eor(moqfetch_seq* s, const moqfetch_obj* o) {
  s->have_loc = 1;
  s->group    = o->group;
  s->object   = o->object;
}

static void moqfetch_note_obj(moqfetch_seq* s, const moqfetch_obj* o) {
  moqfetch_note_eor(s, o);
  s->have_subgroup = o->has_subgroup;
  s->subgroup      = o->subgroup;
  s->have_priority = 1;
  s->priority      = o->priority;
}

/* 0x20C only where the stream's draft has it (draft-22 SS11.4.1). */
static int moqfetch_is_eor(u64 flags, const moqfetch_seq* s) {
  if (flags == MOQFETCH_EOR_TIMED_OUT) return s->eor_timed_out;
  return flags == MOQFETCH_EOR_NONEXISTENT || flags == MOQFETCH_EOR_UNKNOWN;
}

/* 11.4.4: < 128 is a flag set (kind 0), 0x8C / 0x10C (/ 0x20C) an End of
 * Range (kind 1); "Any other value is a PROTOCOL_VIOLATION" (-1). */
static int moqfetch_kind(u64 flags, const moqfetch_seq* s) {
  if (flags < 0x80) return 0;
  return moqfetch_is_eor(flags, s) ? 1 : -1;
}

typedef struct {
  const moqfetch_step_fn* steps;
  usz                     n;
  void (*note)(moqfetch_seq*, const moqfetch_obj*);
} moqfetch_kind_ops;

static const moqfetch_kind_ops MOQFETCH_KIND_OPS[2] = {
    {MOQFETCH_OBJ_STEPS, MOQFETCH_N(MOQFETCH_OBJ_STEPS), moqfetch_note_obj},
    {MOQFETCH_EOR_STEPS, MOQFETCH_N(MOQFETCH_EOR_STEPS), moqfetch_note_eor},
};

static void moqfetch_obj_clear(moqfetch_obj* o, u64 flags) {
  bytes_memset(o, 0, sizeof *o);
  o->flags = flags;
}

/* Runs one kind's take steps, then advances the prior-Object state. */
static int moqfetch_run(
    const moqfetch_kind_ops* ops,
    wired_span               b,
    usz*                     at,
    moqfetch_seq*            s,
    moqfetch_obj*            o) {
  for (usz i = 0; i < ops->n; i++) {
    int r = ops->steps[i](b, at, s, o);
    if (r != MOQCTL_OK) return r;
  }
  ops->note(s, o);
  return MOQCTL_OK;
}

static int moqfetch_obj_take_at(
    wired_span b, usz* at, moqfetch_seq* s, moqfetch_obj* o) {
  u64 flags;
  if (!moqvi_take(b, at, &flags)) return MOQCTL_INSUFFICIENT;
  int kind = moqfetch_kind(flags, s);
  if (kind < 0) return MOQCTL_VIOLATION;
  moqfetch_obj_clear(o, flags);
  return moqfetch_run(&MOQFETCH_KIND_OPS[kind], b, at, s, o);
}

/* The sequence advances on a copy, so a failed decode leaves it as is. */
int moqfetch_obj_take(
    wired_span buf, usz* off, moqfetch_seq* seq, moqfetch_obj* out) {
  usz          at   = *off;
  moqfetch_seq next = *seq;
  int          r    = moqfetch_obj_take_at(buf, &at, &next, out);
  if (r != MOQCTL_OK) return r;
  *seq = next;
  *off = at;
  return MOQCTL_OK;
}

/* ----- encode: the inverse of each take step ----- */

typedef int (*moqfetch_put_fn)(
    wired_mspan, usz*, const moqfetch_seq*, const moqfetch_obj*);

static u64 moqfetch_group_delta(const moqfetch_seq* s, u64 g) {
  if (!s->have_loc) return g;
  return s->descending ? s->group - g - 1 : g - s->group - 1;
}

static int moqfetch_put_flags(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  return moqvi_put(b, at, o->flags);
}

static int moqfetch_put_group(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  if (!(o->flags & MOQFETCH_F_GROUP)) return 1;
  return moqvi_put(b, at, moqfetch_group_delta(s, o->group));
}

/* The Subgroup ID field is on the wire only for mode 0x03 without 0x40. */
static int moqfetch_has_sg_field(u64 flags) {
  return !(flags & MOQFETCH_F_DATAGRAM) &&
         (flags & MOQFETCH_F_SUBGROUP_MASK) == MOQFETCH_F_SUBGROUP_MASK;
}

static int moqfetch_put_subgroup(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  if (!moqfetch_has_sg_field(o->flags)) return 1;
  return moqvi_put(b, at, o->subgroup);
}

static int moqfetch_put_object(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  if (!(o->flags & MOQFETCH_F_OBJECT)) return 1;
  return moqvi_put(
      b, at,
      moqfetch_object_absolute(s, o) ? o->object : o->object - s->object);
}

static int moqfetch_put_priority(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  if (!(o->flags & MOQFETCH_F_PRIORITY)) return 1;
  return moqctl_param_put_uint8(b, at, o->priority);
}

static int moqfetch_put_props(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  if (!(o->flags & MOQFETCH_F_PROPS)) return 1;
  return moqctl_name_put(b, at, o->props);
}

static int moqfetch_put_payload(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  return moqctl_name_put(b, at, o->payload);
}

static int moqfetch_put_eor(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  if (!moqvi_put(b, at, o->group)) return 0;
  return moqvi_put(b, at, o->object);
}

static const moqfetch_put_fn MOQFETCH_PUT_OBJ[] = {
    moqfetch_put_flags,   moqfetch_put_group,    moqfetch_put_subgroup,
    moqfetch_put_object,  moqfetch_put_priority, moqfetch_put_props,
    moqfetch_put_payload,
};
static const moqfetch_put_fn MOQFETCH_PUT_EOR[] = {
    moqfetch_put_flags,
    moqfetch_put_eor,
};

typedef struct {
  const moqfetch_put_fn* steps;
  usz                    n;
} moqfetch_put_ops;

static const moqfetch_put_ops MOQFETCH_PUT_BY_KIND[2] = {
    {MOQFETCH_PUT_OBJ, MOQFETCH_N(MOQFETCH_PUT_OBJ)},
    {MOQFETCH_PUT_EOR, MOQFETCH_N(MOQFETCH_PUT_EOR)},
};

static int moqfetch_put_all(
    const moqfetch_put_ops* ops,
    wired_mspan             b,
    usz*                    at,
    const moqfetch_seq*     s,
    const moqfetch_obj*     o) {
  for (usz i = 0; i < ops->n; i++)
    if (!ops->steps[i](b, at, s, o)) return 0;
  return 1;
}

int moqfetch_obj_put(
    wired_mspan buf, usz* off, moqfetch_seq* seq, const moqfetch_obj* o) {
  int kind = moqfetch_kind(o->flags, seq);
  if (kind < 0) return 0;
  if (!moqfetch_put_all(&MOQFETCH_PUT_BY_KIND[kind], buf, off, seq, o))
    return 0;
  MOQFETCH_KIND_OPS[kind].note(seq, o);
  return 1;
}
