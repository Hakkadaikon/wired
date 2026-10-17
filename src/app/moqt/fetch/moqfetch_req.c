#include "app/moqt/fetch/moqfetch_impl.h"

static void moqfetch_req_range_from_end(moqctl_loc end, moqctl_rangeloc* r);
static void moqfetch_req_standalone_from(
    const moqfetch_fetch* f, moqfetch_req* out);
static void moqfetch_req_from_fetch(const moqfetch_fetch* f, moqfetch_req* out);
static moqctl_loc moqfetch_req_end_to_loc(const moqctl_rangeloc* r);
static void moqfetch_req_to_fetch(const moqfetch_req* m, moqfetch_fetch* f);
static int  moqfetch_req19_unrepresentable(const moqfetch_req* m);
static int  moqfetch_req22_take_head(wired_span b, usz* at, moqfetch_req* m);
static void moqfetch_req22_range_default(moqctl_rangeloc* r);
static void moqfetch_req22_range_from_params(moqfetch_req* m);

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
  if (r != MOQCTL_OK) {
    return r;
  }
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

/* 10.12.1: a d19 Standalone Fetch has an absolute Start and a bounded End
 * Location ("plus 1", Object 0 = whole group); an open end or a relative
 * start has no d19 wire form, so it is refused rather than mis-encoded. */
static int moqfetch_req19_unrepresentable(const moqfetch_req* m) {
  return !m->is_joining &&
         (m->range.ek == MOQCTL_REK_UNBOUNDED || m->range.sk != MOQCTL_RSK_ABS);
}

int moqfetch_req19_encode(wired_mspan buf, usz* off, const moqfetch_req* m) {
  moqfetch_fetch f = {0};
  if (moqfetch_req19_unrepresentable(m)) {
    return 0;
  }
  moqfetch_req_to_fetch(m, &f);
  return moqfetch_fetch_encode(buf, off, &f);
}

/* draft-22 FETCH body: Request ID, Track Namespace, Track Name, Parameters
 * (draft-22 parameters, so LOCATION_FILTER decodes per SS9.20.9, not d19's
 * Length-prefixed SS5.1.2 shape). */
static int moqfetch_req22_take_head(wired_span b, usz* at, moqfetch_req* m) {
  if (!moqvi_take(b, at, &m->request_id)) {
    return MOQCTL_INSUFFICIENT;
  }
  return moqctl_ftn_take(b, at, &m->track); /* SS2.4.1 FTN <= 4096 */
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
  if (r == MOQCTL_OK) {
    r = moqctl_params_take(
        MOQVER_D22, body, &at, MOQCTL_PCTX_FETCH, &out->params);
  }
  r = moqctl_body_end(r, at, body);
  if (r != MOQCTL_OK) {
    return r;
  }
  out->is_joining = 0;
  out->fetch_type = MOQFETCH_STANDALONE;
  moqfetch_req22_range_from_params(out);
  return MOQCTL_OK;
}
