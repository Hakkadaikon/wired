#include "app/moqt/ns/moqns.h"

#include "app/moqt/vi/moqvi.h"

/* draft-ietf-moq-transport-19 2.4.1: "If an endpoint receives a Track
 * Namespace ... exceeding 4,096 bytes, it MUST close the session with a
 * PROTOCOL_VIOLATION" (namespace length = sum of the field lengths). */
static int moqns_tuple_bound(const moqctl_ns* ns) {
  return moqctl_ns_bytelen(ns) > MOQCTL_MAX_FTN_LEN ? MOQCTL_VIOLATION
                                                    : MOQCTL_OK;
}

int moqns_tuple_take(wired_span buf, usz* off, moqctl_ns* out) {
  int r = moqctl_ns_take(buf, off, out);
  if (r != MOQCTL_OK) return r;
  return moqns_tuple_bound(out);
}

/* 10.15 Figure 17 / 10.18 Figure 20: Request ID, Track Namespace (Prefix),
 * Number of Parameters, Parameters. */
static int moqns_req_take_head(wired_span body, usz* at, moqns_req* out) {
  if (!moqvi_take(body, at, &out->request_id)) return MOQCTL_INSUFFICIENT;
  return moqns_tuple_take(body, at, &out->ns);
}

static int moqns_req_take(wired_span body, u32 ctx, moqns_req* out) {
  usz at = 0;
  int r  = moqns_req_take_head(body, &at, out);
  if (r == MOQCTL_OK) r = moqctl_params_take(body, &at, ctx, &out->params);
  return moqctl_body_end(r, at, body);
}

int moqns_subscribe_take(wired_span body, moqns_req* out) {
  return moqns_req_take(body, MOQCTL_PCTX_SUBSCRIBE_NAMESPACE, out);
}

int moqns_publish_take(wired_span body, moqns_req* out) {
  return moqns_req_take(body, MOQCTL_PCTX_PUBLISH_NAMESPACE, out);
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
  return moqctl_body_end(moqns_tuple_take(body, &at, out), at, body);
}
