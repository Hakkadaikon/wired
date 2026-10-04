#include "app/moqt/ns/moqns.h"

#include "app/moqt/vi/moqvi.h"

/* 10.15 Figure 17 / 10.18 Figure 20: Request ID, Track Namespace (Prefix),
 * Number of Parameters, Parameters. */
static int moqns_req_take_head(wired_span body, usz* at, moqns_req* out) {
  if (!moqvi_take(body, at, &out->request_id)) return MOQCTL_INSUFFICIENT;
  return moqctl_ns_take(body, at, &out->ns);
}

static int moqns_req_take(int ver, wired_span body, u32 ctx, moqns_req* out) {
  usz at = 0;
  int r  = moqns_req_take_head(body, &at, out);
  if (r == MOQCTL_OK) r = moqctl_params_take(ver, body, &at, ctx, &out->params);
  return moqctl_body_end(r, at, body);
}

int moqns_subscribe_take(int ver, wired_span body, moqns_req* out) {
  return moqns_req_take(ver, body, MOQCTL_PCTX_SUBSCRIBE_NAMESPACE, out);
}

int moqns_publish_take(int ver, wired_span body, moqns_req* out) {
  return moqns_req_take(ver, body, MOQCTL_PCTX_PUBLISH_NAMESPACE, out);
}

int moqns_subscribe_tracks_take(int ver, wired_span body, moqns_req* out) {
  return moqns_req_take(ver, body, MOQCTL_PCTX_SUBSCRIBE_TRACKS, out);
}

int moqns_req_encode(wired_mspan buf, usz* off, const moqns_req* m) {
  if (!moqvi_put(buf, off, m->request_id)) return 0;
  if (!moqctl_ns_put(buf, off, &m->ns)) return 0;
  return moqctl_params_put(buf, off, &m->params);
}

/* 10.16 Figure 18 / 10.17 Figure 19: the body is the Track Namespace
 * Suffix alone. */
int moqns_suffix_take(wired_span body, moqctl_ns* out) {
  usz at = 0;
  return moqctl_body_end(moqctl_ns_take(body, &at, out), at, body);
}

/* 10.20: Track Namespace Suffix then Track Name. */
int moqns_pub_skipped_take(wired_span body, moqns_pub_skipped* out) {
  usz at = 0;
  int r  = moqctl_ns_take(body, &at, &out->ns);
  if (r == MOQCTL_OK) r = moqctl_name_take(body, &at, &out->name);
  return moqctl_body_end(r, at, body);
}

int moqns_pub_skipped_encode(
    wired_mspan buf, usz* off, const moqns_pub_skipped* m) {
  if (!moqctl_ns_put(buf, off, &m->ns)) return 0;
  return moqctl_name_put(buf, off, m->name);
}
