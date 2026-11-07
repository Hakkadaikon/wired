#include "app/moqt/fetch/moqfetch_impl.h"

/* The draft-23 FETCH response: a REQUEST_OK body (9.3). */

static void moqfetch_ok23_largest(moqfetch_ok* m);
static int  moqfetch_ok23_params(const moqfetch_ok* m, moqctl_params* p);

static void moqfetch_ok23_largest(moqfetch_ok* m) {
  const moqctl_param* lo =
      moqctl_params_find(&m->params, MOQCTL_PARAM_LARGEST_OBJECT);
  m->has_largest = lo != 0;
  if (lo) {
    m->end = lo->loc;
  }
}

/* draft-23 9.3: Parameters, then Track Properties to the end. */
int moqfetch_ok23_take(int ver, wired_span body, moqfetch_ok* out) {
  usz at = 0;
  int r;
  bytes_memset(out, 0, sizeof *out);
  r = moqctl_params_take(ver, body, &at, MOQCTL_PCTX_FETCH_OK, &out->params);
  out->track_properties = wired_span_of(body.p + at, body.n - at);
  moqfetch_ok23_largest(out);
  return moqctl_body_end(r, body.n, body);
}

/* m's Parameters, then LARGEST_OBJECT: every other FETCH_OK Parameter
 * (EXPIRES 0x08) has a lower Type, so the list stays ascending. */
static int moqfetch_ok23_params(const moqfetch_ok* m, moqctl_params* p) {
  *p = m->params;
  if (!m->has_largest) {
    return 1;
  }
  if (p->n >= MOQCTL_MAX_PARAMS) {
    return 0;
  }
  p->items[p->n]      = (moqctl_param){0};
  p->items[p->n].type = MOQCTL_PARAM_LARGEST_OBJECT;
  p->items[p->n].enc  = MOQCTL_PENC_LOCATION;
  p->items[p->n].loc  = m->end;
  p->n++;
  return 1;
}

int moqfetch_ok23_encode(wired_mspan buf, usz* off, const moqfetch_ok* m) {
  moqctl_params p;
  if (!moqfetch_ok23_params(m, &p) || !moqctl_params_put(buf, off, &p)) {
    return 0;
  }
  return bytes_put(buf, off, m->track_properties);
}
