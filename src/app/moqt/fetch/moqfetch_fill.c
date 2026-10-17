#include "app/moqt/fetch/moqfetch_impl.h"

static usz  moqfetch_req22_filter_slot(const moqctl_params* params);
static void moqfetch_req22_put_filter(moqfetch_req* m);
static int  moqfetch_req22_put_head(
    wired_mspan buf, usz* off, const moqfetch_req* m);
static int  moqfetch_fill_params(wired_span v, moqctl_params* p);
static void moqfetch_fill_filter_of(const moqctl_params* p, moqfetch_fill* o);
static int  moqfetch_fill_desc_of(const moqctl_params* p);
static void moqfetch_fill_tmo_of(const moqctl_params* p, moqfetch_fill* o);
static usz  moqfetch_fill_items(const moqfetch_fill* f, moqctl_params* p);

/* Re-derives the LOCATION_FILTER parameter from m->range (always present
 * on encode: the "fetch everything" default and an explicit filter use the
 * same moqctl_rangeloc22_put(has_filter=1, ...) shape as any other
 * absolute-start/open-ended filter -- a receiver cannot tell them apart on
 * the wire, nor needs to). */
static usz moqfetch_req22_filter_slot(const moqctl_params* params) {
  usz i;
  for (i = 0; i < params->n; i++) {
    if (params->items[i].type >= MOQCTL_PARAM_LOCATION_FILTER) {
      break;
    }
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
  if (moqctl_params_find(&m->params, MOQCTL_PARAM_LOCATION_FILTER)) {
    return;
  }
  slot = moqfetch_req22_filter_slot(&m->params);
  for (j = m->params.n; j > slot; j--) {
    m->params.items[j] = m->params.items[j - 1];
  }
  p             = &m->params.items[slot];
  p->type       = MOQCTL_PARAM_LOCATION_FILTER;
  p->enc        = MOQCTL_PENC_RANGELOC22;
  p->has_filter = 1;
  p->rl         = m->range;
  m->params.n++;
}

static int moqfetch_req22_put_head(
    wired_mspan buf, usz* off, const moqfetch_req* m) {
  if (!moqvi_put(buf, off, m->request_id)) {
    return 0;
  }
  return moqctl_ns_put(buf, off, &m->track.ns);
}

int moqfetch_req22_encode(wired_mspan buf, usz* off, const moqfetch_req* m) {
  moqfetch_req tmp = *m;
  moqfetch_req22_put_filter(&tmp);
  if (!moqfetch_req22_put_head(buf, off, &tmp)) {
    return 0;
  }
  if (!moqctl_name_put(buf, off, tmp.track.name)) {
    return 0;
  }
  return moqctl_params_put(buf, off, &tmp.params);
}

/* ===== FILL_PARAMETERS value (draft-22 SS9.20.15) ===== */

/* The Parameters must fill the value exactly (its Length already framed
 * it). */
static int moqfetch_fill_params(wired_span v, moqctl_params* p) {
  usz at = 0;
  int r  = moqctl_params_take(MOQVER_D22, v, &at, MOQCTL_PCTX_FETCH, p);
  if (r != MOQCTL_OK) {
    return r;
  }
  return at == v.n ? MOQCTL_OK : MOQCTL_VIOLATION;
}

/* LOCATION_FILTER type 0x00 decodes as has_filter 0 (SS9.20.9 None); an
 * absent one defers to the subscription's filter (SS3.4: inherit). */
static void moqfetch_fill_filter_of(const moqctl_params* p, moqfetch_fill* o) {
  const moqctl_param* lf = moqctl_params_find(p, MOQCTL_PARAM_LOCATION_FILTER);
  o->inherit             = lf == 0;
  if (!lf || !lf->has_filter) {
    return;
  }
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
  if (to) {
    o->timeout_ms = to->vi;
  }
}

int moqfetch_fill_take(wired_span value, moqfetch_fill* out) {
  moqctl_params p;
  p.n = 0; /* a zero-length value is "no parameters" */
  bytes_memset(out, 0, sizeof *out);
  if (value.n != 0) { /* zero-length: the whole track (Q-02) */
    int r = moqfetch_fill_params(value, &p);
    if (r != MOQCTL_OK) {
      return r;
    }
    moqfetch_fill_filter_of(&p, out);
  }
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
