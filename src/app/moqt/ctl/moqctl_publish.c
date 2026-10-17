#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_publish_take_id_name(
    wired_span buf, usz* at, moqctl_publish* out);
static int moqctl_publish_encode_head(
    wired_mspan buf, usz* at, const moqctl_publish* m);
static int moqctl_publish_encode_tail(
    wired_mspan buf, usz* at, const moqctl_publish* m);
static int moqctl_redirect_take_uri(
    wired_span buf, usz* at, moqctl_redirect* r);
static int moqctl_redirect_take_target(
    wired_span buf, usz* at, moqctl_redirect* r);

static int moqctl_publish_take_id_name(
    wired_span buf, usz* at, moqctl_publish* out) {
  if (!moqvi_take(buf, at, &out->request_id)) return MOQCTL_INSUFFICIENT;
  return moqctl_ftn_take(buf, at, &out->name);
}

int moqctl_publish_take(
    int ver, wired_span buf, usz* off, moqctl_publish* out) {
  usz at = *off;
  int r  = moqctl_publish_take_id_name(buf, &at, out);
  if (r != MOQCTL_OK) return r;
  r = moqctl_publish_take_alias_params(ver, buf, &at, out);
  if (r != MOQCTL_OK) return r;
  *off = buf.n;
  return MOQCTL_OK;
}

static int moqctl_publish_encode_head(
    wired_mspan buf, usz* at, const moqctl_publish* m) {
  if (!moqvi_put(buf, at, m->request_id)) return 0;
  return moqctl_ftn_put(buf, at, &m->name);
}

static int moqctl_publish_encode_tail(
    wired_mspan buf, usz* at, const moqctl_publish* m) {
  if (!moqvi_put(buf, at, m->track_alias)) return 0;
  if (!moqctl_params_put(buf, at, &m->params)) return 0;
  return bytes_put(buf, at, m->track_properties);
}

int moqctl_publish_encode(wired_mspan buf, usz* off, const moqctl_publish* m) {
  usz at = *off;
  if (!moqctl_publish_encode_head(buf, &at, m)) return 0;
  if (!moqctl_publish_encode_tail(buf, &at, m)) return 0;
  *off = at;
  return 1;
}

/* ===== REQUEST_OK (SS10.5) =====
 * Parameters use the scope of whichever request REQUEST_OK answers, which
 * this codec does not track (session-layer concern), so it admits the
 * union of every OK's scope. */
int moqctl_request_ok_take(
    int ver, wired_span buf, usz* off, moqctl_request_ok* out) {
  usz at = *off;
  int r  = moqctl_params_take(
      ver, buf, &at, MOQCTL_PCTX_REQUEST_OK_ANY, &out->params);
  if (r != MOQCTL_OK) return r;
  out->track_properties = moqctl_residual(buf, at);
  *off                  = buf.n;
  return MOQCTL_OK;
}

int moqctl_request_ok_encode(
    wired_mspan buf, usz* off, const moqctl_request_ok* m) {
  usz at = *off;
  if (!moqctl_params_put(buf, &at, &m->params)) return 0;
  if (!bytes_put(buf, &at, m->track_properties)) return 0;
  *off = at;
  return 1;
}

/* ===== REQUEST_ERROR (SS10.8) ===== */

static int moqctl_redirect_take_uri(
    wired_span buf, usz* at, moqctl_redirect* r) {
  u64 uri_len;
  if (!moqctl_span_take_len(buf, at, &uri_len)) return MOQCTL_INSUFFICIENT;
  return moqctl_bytes_take(buf, at, uri_len, &r->connect_uri);
}

/* d22 SS9.4.1: the Redirect target is a Full Track Name (SS2.4.1 bound). */
static int moqctl_redirect_take_target(
    wired_span buf, usz* at, moqctl_redirect* r) {
  moqctl_ftn f;
  int        rr = moqctl_ftn_take(buf, at, &f);
  if (rr != MOQCTL_OK) return rr;
  r->track_namespace = f.ns;
  r->track_name      = f.name;
  return MOQCTL_OK;
}

int moqctl_redirect_take(wired_span buf, usz* at, moqctl_redirect* r) {
  int rr = moqctl_redirect_take_uri(buf, at, r);
  if (rr != MOQCTL_OK) return rr;
  return moqctl_redirect_take_target(buf, at, r);
}
