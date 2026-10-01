#include "app/moqt/tstat/moqtstat.h"

#include "app/moqt/vi/moqvi.h"

/* draft-ietf-moq-transport-19 10.14: TRACK_STATUS has SUBSCRIBE's layout
 * (Request ID, Track Namespace, Track Name, Parameters); its parameters
 * are checked against the TRACK_STATUS scope instead of SUBSCRIBE's. */
static int moqtstat_take_body(wired_span body, usz* at, moqctl_subscribe* out) {
  int r = moqctl_ftn_take(body, at, &out->name);
  if (r != MOQCTL_OK) return r;
  return moqctl_params_take(body, at, MOQCTL_PCTX_TRACK_STATUS, &out->params);
}

int moqtstat_take(wired_span body, moqctl_subscribe* out) {
  usz at = 0;
  int r  = MOQCTL_INSUFFICIENT;
  if (moqvi_take(body, &at, &out->request_id))
    r = moqtstat_take_body(body, &at, out);
  return moqctl_body_end(r, at, body);
}

/* 10.5 Figure 8 answering TRACK_STATUS (10.14): Parameters, then the
 * Track Properties as the rest of the body. */
int moqtstat_ok_take(wired_span body, moqctl_request_ok* out) {
  usz at = 0;
  int r =
      moqctl_params_take(body, &at, MOQCTL_PCTX_TRACK_STATUS_OK, &out->params);
  out->track_properties = wired_span_of(body.p + at, body.n - at);
  return moqctl_body_end(r, body.n, body);
}

/* 10.9 Figure 12: Request ID, Number of Parameters, Parameters. */
int moqtstat_update_take(wired_span body, u32 ctx, moqtstat_update* out) {
  usz at = 0;
  int r  = MOQCTL_INSUFFICIENT;
  if (moqvi_take(body, &at, &out->request_id))
    r = moqctl_params_take(body, &at, ctx, &out->params);
  return moqctl_body_end(r, at, body);
}

int moqtstat_update_encode(
    wired_mspan buf, usz* off, const moqtstat_update* m) {
  if (!moqvi_put(buf, off, m->request_id)) return 0;
  return moqctl_params_put(buf, off, &m->params);
}
