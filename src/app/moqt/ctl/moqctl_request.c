#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_request_error_take_redirect(
    wired_span buf, usz* at, moqctl_request_error* out);
static int moqctl_request_error_take_codes(
    wired_span buf, usz* at, moqctl_request_error* out);
static int moqctl_request_error_take_reason_redirect(
    wired_span buf, usz* at, moqctl_request_error* out);
static int moqctl_redirect_put_uri(
    wired_mspan buf, usz* at, const moqctl_redirect* r);
static int moqctl_redirect_put_name(
    wired_mspan buf, usz* at, const moqctl_redirect* r);
static int moqctl_redirect_put(
    wired_mspan buf, usz* at, const moqctl_redirect* r);
static int moqctl_request_error_encode_codes_reason(
    wired_mspan buf, usz* at, const moqctl_request_error* m);
static int moqctl_request_error_encode_redirect(
    wired_mspan buf, usz* at, const moqctl_request_error* m);

static int moqctl_request_error_take_redirect(
    wired_span buf, usz* at, moqctl_request_error* out) {
  if (out->error_code != MOQCTL_ERR_REDIRECT) {
    out->has_redirect = 0;
    return MOQCTL_OK;
  }
  out->has_redirect = 1;
  return moqctl_redirect_take(buf, at, &out->redirect);
}

static int moqctl_request_error_take_codes(
    wired_span buf, usz* at, moqctl_request_error* out) {
  if (!moqvi_take(buf, at, &out->error_code)) {
    return MOQCTL_INSUFFICIENT;
  }
  if (!moqvi_take(buf, at, &out->retry_interval)) {
    return MOQCTL_INSUFFICIENT;
  }
  return MOQCTL_OK;
}

static int moqctl_request_error_take_reason_redirect(
    wired_span buf, usz* at, moqctl_request_error* out) {
  int r = moqctl_reason_take(buf, at, &out->reason);
  if (r != MOQCTL_OK) {
    return r;
  }
  return moqctl_request_error_take_redirect(buf, at, out);
}

int moqctl_request_error_take(
    wired_span buf, usz* off, moqctl_request_error* out) {
  usz at = *off;
  int r  = moqctl_request_error_take_codes(buf, &at, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  r = moqctl_request_error_take_reason_redirect(buf, &at, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  *off = at;
  return MOQCTL_OK;
}

static int moqctl_redirect_put_uri(
    wired_mspan buf, usz* at, const moqctl_redirect* r) {
  if (!moqvi_put(buf, at, r->connect_uri.n)) {
    return 0;
  }
  return bytes_put(buf, at, r->connect_uri);
}

static int moqctl_redirect_put_name(
    wired_mspan buf, usz* at, const moqctl_redirect* r) {
  if (!moqvi_put(buf, at, r->track_name.n)) {
    return 0;
  }
  return bytes_put(buf, at, r->track_name);
}

static int moqctl_redirect_put(
    wired_mspan buf, usz* at, const moqctl_redirect* r) {
  if (!moqctl_redirect_put_uri(buf, at, r)) {
    return 0;
  }
  if (!moqctl_ns_put(buf, at, &r->track_namespace)) {
    return 0;
  }
  return moqctl_redirect_put_name(buf, at, r);
}

static int moqctl_request_error_encode_codes_reason(
    wired_mspan buf, usz* at, const moqctl_request_error* m) {
  if (!moqvi_put(buf, at, m->error_code)) {
    return 0;
  }
  if (!moqvi_put(buf, at, m->retry_interval)) {
    return 0;
  }
  return moqctl_reason_put(buf, at, m->reason);
}

static int moqctl_request_error_encode_redirect(
    wired_mspan buf, usz* at, const moqctl_request_error* m) {
  if (!m->has_redirect) {
    return 1;
  }
  return moqctl_redirect_put(buf, at, &m->redirect);
}

int moqctl_request_error_encode(
    wired_mspan buf, usz* off, const moqctl_request_error* m) {
  usz at = *off;
  if (!moqctl_request_error_encode_codes_reason(buf, &at, m)) {
    return 0;
  }
  if (!moqctl_request_error_encode_redirect(buf, &at, m)) {
    return 0;
  }
  *off = at;
  return 1;
}
