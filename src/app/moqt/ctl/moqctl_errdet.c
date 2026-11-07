#include "app/moqt/ctl/moqctl_impl.h"

/* draft-ietf-moq-transport-23 9.4.1 / 9.4.2: REQUEST_ERROR ends in Error
 * Details, Key-Value-Pairs (8.3) to the end of the message. */

static int moqctl_detail_short(int r);
static int moqctl_detail_redirect_exact(wired_span v, moqctl_redirect* red);
static int moqctl_detail_redirect(moqctl_request_error* out, const moqkvp* kv);
static int moqctl_detail_unsupp_room(const moqctl_request_error* out);
static int moqctl_detail_unsupp(moqctl_request_error* out, const moqkvp* kv);
static int moqctl_detail_one(moqctl_request_error* out, const moqkvp* kv);
static int moqctl_details_step(
    wired_span buf, usz* at, u64* prev, moqctl_request_error* out);
static int moqctl_details_take(
    wired_span buf, usz* at, moqctl_request_error* out);
static int moqctl_details_complete(const moqctl_request_error* out);
static int moqctl_details_all(
    wired_span buf, usz* at, moqctl_request_error* out);
static int moqctl_request_error_take23(
    wired_span buf, usz* off, moqctl_request_error* out);

/* A detail value cut short does not match its Type's definition (8.3). */
static int moqctl_detail_short(int r) {
  return r == MOQCTL_INSUFFICIENT ? MOQCTL_PARAMS_KVFMT : r;
}

/* 9.4.2.1: the REDIRECT value is exactly one Redirect -- Connect URI
 * Length, Connect URI, Track Namespace, Track Name Length, Track Name. */
static int moqctl_detail_redirect_exact(wired_span v, moqctl_redirect* red) {
  usz at = 0;
  int r  = moqctl_detail_short(moqctl_redirect_take(v, &at, red));
  if (r != MOQCTL_OK) {
    return r;
  }
  return at == v.n ? MOQCTL_OK : MOQCTL_PARAMS_KVFMT;
}

/* With Error Code REDIRECT the first REDIRECT detail names the target
 * (later ones are ignored); with any other code it is ignored (9.4.2). */
static int moqctl_detail_redirect(moqctl_request_error* out, const moqkvp* kv) {
  int r;
  if (out->error_code != MOQCTL_ERR_REDIRECT || out->has_redirect) {
    return MOQCTL_OK;
  }
  r                 = moqctl_detail_redirect_exact(kv->raw, &out->redirect);
  out->has_redirect = r == MOQCTL_OK;
  return r;
}

/* 9.4.2.2: kept with UNSUPPORTED_EXTENSION only, the first
 * MOQCTL_MAX_UNSUPP of them. */
static int moqctl_detail_unsupp_room(const moqctl_request_error* out) {
  return out->error_code == MOQCTL_ERR_UNSUPPORTED_EXTENSION &&
         out->n_unsupported < MOQCTL_MAX_UNSUPP;
}

static int moqctl_detail_unsupp(moqctl_request_error* out, const moqkvp* kv) {
  if (moqctl_detail_unsupp_room(out)) {
    out->unsupported[out->n_unsupported++] = kv->num;
  }
  return MOQCTL_OK;
}

/* One Error Detail: an unknown Type is ignored, repeats included
 * (9.4.2). */
static int moqctl_detail_one(moqctl_request_error* out, const moqkvp* kv) {
  if (kv->type == MOQCTL_DETAIL_REDIRECT) {
    return moqctl_detail_redirect(out, kv);
  }
  if (kv->type == MOQCTL_DETAIL_UNSUPPORTED_PROPERTY) {
    return moqctl_detail_unsupp(out, kv);
  }
  return MOQCTL_OK;
}

/* One pair: a Type past 2^64-1 is MOQCTL_R_DELTA, an odd Type's Length
 * past 65535 MOQCTL_R_FIELD_LEN, a cut pair a Length mismatch (8.3). */
static int moqctl_details_step(
    wired_span buf, usz* at, u64* prev, moqctl_request_error* out) {
  moqkvp kv;
  int    r = moqkvp_take(buf, at, prev, &kv);
  if (r != MOQKVP_OK) {
    return moqctl_kvp_r(r);
  }
  return moqctl_detail_one(out, &kv);
}

static int moqctl_details_take(
    wired_span buf, usz* at, moqctl_request_error* out) {
  u64 prev = 0;
  while (*at < buf.n) {
    int r = moqctl_details_step(buf, at, &prev, out);
    if (r != MOQCTL_OK) {
      return r;
    }
  }
  return MOQCTL_OK;
}

/* 9.4.2.1: REDIRECT without a REDIRECT detail is MALFORMED_MESSAGE. */
static int moqctl_details_complete(const moqctl_request_error* out) {
  return out->error_code == MOQCTL_ERR_REDIRECT && !out->has_redirect
             ? MOQCTL_VIOLATION
             : MOQCTL_OK;
}

static int moqctl_details_all(
    wired_span buf, usz* at, moqctl_request_error* out) {
  int r = moqctl_details_take(buf, at, out);
  return r == MOQCTL_OK ? moqctl_details_complete(out) : r;
}

static int moqctl_request_error_take23(
    wired_span buf, usz* off, moqctl_request_error* out) {
  usz at = *off;
  int r  = moqctl_request_error_take_head(buf, &at, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  r = moqctl_details_all(buf, &at, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  *off = at;
  return MOQCTL_OK;
}

int moqctl_request_error_take_v(
    int ver, wired_span buf, usz* off, moqctl_request_error* out) {
  return (moqver_caps(ver) & MOQVER_CAP_ERR_DETAILS)
             ? moqctl_request_error_take23(buf, off, out)
             : moqctl_request_error_take(buf, off, out);
}
