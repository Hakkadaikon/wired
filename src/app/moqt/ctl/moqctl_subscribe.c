#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_subscribe_take_body(
    int ver, wired_span buf, usz* at, moqctl_subscribe* out);
static int moqctl_subscribe_encode_head(
    wired_mspan buf, usz* at, const moqctl_subscribe* m);
static int moqctl_subscribe_ok_encode_head(
    wired_mspan buf, usz* at, const moqctl_subscribe_ok* m);

/* ===== SUBSCRIBE (SS10.6) ===== */

static int moqctl_subscribe_take_body(
    int ver, wired_span buf, usz* at, moqctl_subscribe* out) {
  int r = moqctl_ftn_take(buf, at, &out->name);
  if (r != MOQCTL_OK) return r;
  return moqctl_params_take(ver, buf, at, MOQCTL_PCTX_SUBSCRIBE, &out->params);
}

int moqctl_subscribe_take(
    int ver, wired_span buf, usz* off, moqctl_subscribe* out) {
  usz at = *off;
  int r;
  if (!moqvi_take(buf, &at, &out->request_id)) return MOQCTL_INSUFFICIENT;
  r = moqctl_subscribe_take_body(ver, buf, &at, out);
  if (r != MOQCTL_OK) return r;
  *off = at;
  return MOQCTL_OK;
}

static int moqctl_subscribe_encode_head(
    wired_mspan buf, usz* at, const moqctl_subscribe* m) {
  if (!moqvi_put(buf, at, m->request_id)) return 0;
  return moqctl_ftn_put(buf, at, &m->name);
}

int moqctl_subscribe_encode(
    wired_mspan buf, usz* off, const moqctl_subscribe* m) {
  usz at = *off;
  if (!moqctl_subscribe_encode_head(buf, &at, m)) return 0;
  if (!moqctl_params_put(buf, &at, &m->params)) return 0;
  *off = at;
  return 1;
}

/* ===== SUBSCRIBE_OK (SS10.7) ===== */

wired_span moqctl_residual(wired_span buf, usz at) {
  return wired_span_of(buf.p + at, buf.n - at);
}

int moqctl_subscribe_ok_take(
    int ver, wired_span buf, usz* off, moqctl_subscribe_ok* out) {
  usz at = *off;
  int r;
  if (!moqvi_take(buf, &at, &out->track_alias)) return MOQCTL_INSUFFICIENT;
  r = moqctl_params_take(ver, buf, &at, MOQCTL_PCTX_SUBSCRIBE_OK, &out->params);
  if (r != MOQCTL_OK) return r;
  out->track_properties = moqctl_residual(buf, at);
  *off                  = buf.n;
  return MOQCTL_OK;
}

static int moqctl_subscribe_ok_encode_head(
    wired_mspan buf, usz* at, const moqctl_subscribe_ok* m) {
  if (!moqvi_put(buf, at, m->track_alias)) return 0;
  return moqctl_params_put(buf, at, &m->params);
}

int moqctl_subscribe_ok_encode(
    wired_mspan buf, usz* off, const moqctl_subscribe_ok* m) {
  usz at = *off;
  if (!moqctl_subscribe_ok_encode_head(buf, &at, m)) return 0;
  if (!bytes_put(buf, &at, m->track_properties)) return 0;
  *off = at;
  return 1;
}

/* ===== PUBLISH (SS10.9) ===== */

int moqctl_publish_take_alias_params(
    int ver, wired_span buf, usz* at, moqctl_publish* out) {
  int r;
  if (!moqvi_take(buf, at, &out->track_alias)) return MOQCTL_INSUFFICIENT;
  r = moqctl_params_take(ver, buf, at, MOQCTL_PCTX_PUBLISH, &out->params);
  if (r != MOQCTL_OK) return r;
  out->track_properties = moqctl_residual(buf, *at);
  return MOQCTL_OK;
}
