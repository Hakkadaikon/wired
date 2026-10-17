#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_publish_done_take_codes(
    wired_span buf, usz* at, moqctl_publish_done* out);
static int moqctl_publish_done_encode_codes(
    wired_mspan buf, usz* at, const moqctl_publish_done* m);
static int moqctl_goaway_take_uri(wired_span buf, usz* at, moqctl_goaway* out);
static int moqctl_goaway_encode_uri(
    wired_mspan buf, usz* at, const moqctl_goaway* m);

/* ===== PUBLISH_DONE (SS10.10) ===== */

static int moqctl_publish_done_take_codes(
    wired_span buf, usz* at, moqctl_publish_done* out) {
  if (!moqvi_take(buf, at, &out->status_code)) {
    return MOQCTL_INSUFFICIENT;
  }
  if (!moqvi_take(buf, at, &out->stream_count)) {
    return MOQCTL_INSUFFICIENT;
  }
  return MOQCTL_OK;
}

int moqctl_publish_done_take(
    wired_span buf, usz* off, moqctl_publish_done* out) {
  usz at = *off;
  int r  = moqctl_publish_done_take_codes(buf, &at, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  r = moqctl_reason_take(buf, &at, &out->reason);
  if (r != MOQCTL_OK) {
    return r;
  }
  *off = at;
  return MOQCTL_OK;
}

static int moqctl_publish_done_encode_codes(
    wired_mspan buf, usz* at, const moqctl_publish_done* m) {
  if (!moqvi_put(buf, at, m->status_code)) {
    return 0;
  }
  return moqvi_put(buf, at, m->stream_count);
}

int moqctl_publish_done_encode(
    wired_mspan buf, usz* off, const moqctl_publish_done* m) {
  usz at = *off;
  if (!moqctl_publish_done_encode_codes(buf, &at, m)) {
    return 0;
  }
  if (!moqctl_reason_put(buf, &at, m->reason)) {
    return 0;
  }
  *off = at;
  return 1;
}

/* ===== GOAWAY (SS10.3) ===== */

static int moqctl_goaway_take_uri(wired_span buf, usz* at, moqctl_goaway* out) {
  u64 uri_len;
  if (!moqctl_span_take_len(buf, at, &uri_len)) {
    return MOQCTL_INSUFFICIENT;
  }
  if (uri_len > MOQCTL_MAX_URI_LEN) {
    return MOQCTL_VIOLATION;
  }
  return moqctl_bytes_take(buf, at, uri_len, &out->new_session_uri);
}

int moqctl_goaway_take(wired_span buf, usz* off, moqctl_goaway* out) {
  usz at = *off;
  int r  = moqctl_goaway_take_uri(buf, &at, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  if (!moqvi_take(buf, &at, &out->timeout)) {
    return MOQCTL_INSUFFICIENT;
  }
  *off = at;
  return MOQCTL_OK;
}

static int moqctl_goaway_encode_uri(
    wired_mspan buf, usz* at, const moqctl_goaway* m) {
  if (!moqvi_put(buf, at, m->new_session_uri.n)) {
    return 0;
  }
  return bytes_put(buf, at, m->new_session_uri);
}

int moqctl_goaway_encode(wired_mspan buf, usz* off, const moqctl_goaway* m) {
  usz at = *off;
  if (!moqctl_goaway_encode_uri(buf, &at, m)) {
    return 0;
  }
  if (!moqvi_put(buf, &at, m->timeout)) {
    return 0;
  }
  *off = at;
  return 1;
}

int moqctl_goaway18_take(wired_span buf, usz* off, moqctl_goaway* out) {
  usz at = *off;
  int r  = moqctl_goaway_take(buf, &at, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  if (!moqvi_take(buf, &at, &out->request_id)) {
    return MOQCTL_INSUFFICIENT;
  }
  *off = at;
  return MOQCTL_OK;
}

int moqctl_goaway18_encode(wired_mspan buf, usz* off, const moqctl_goaway* m) {
  if (!moqctl_goaway_encode(buf, off, m)) {
    return 0;
  }
  return moqvi_put(buf, off, m->request_id);
}
