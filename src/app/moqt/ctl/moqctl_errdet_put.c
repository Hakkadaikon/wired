#include "app/moqt/ctl/moqctl_impl.h"

/* draft-ietf-moq-transport-23 9.4.1 / 9.4.2: REQUEST_ERROR Error Details
 * written (moqctl_errdet.c reads them). */

static int moqctl_detail_head_move(wired_mspan buf, usz* at, usz body, usz n);
static int moqctl_detail_put_redirect(
    wired_mspan buf, usz* at, const moqctl_redirect* red);
static usz moqctl_detail_unsupp_n(const moqctl_request_error* m);
static int moqctl_details_put_unsupp(
    wired_mspan buf, usz* at, u64* prev, const moqctl_request_error* m);
static int moqctl_details_put(
    wired_mspan buf, usz* at, const moqctl_request_error* m);

/* The n Redirect bytes at body become the REDIRECT detail at *at: Delta
 * Type 1 (the first detail), Length, value moved down to meet them. */
static int moqctl_detail_head_move(wired_mspan buf, usz* at, usz body, usz n) {
  if (n > MOQKVP_MAX_LEN) {
    return 0;
  }
  buf.p[(*at)++] = (u8)MOQCTL_DETAIL_REDIRECT;
  moqvi_put(buf, at, n); /* fits: body leaves room for the longest */
  bytes_move_down(buf.p + *at, buf.p + body, n);
  *at += n;
  return 1;
}

/* The Redirect is written past room for the longest detail header, then
 * moved down once its Length is known. */
static int moqctl_detail_put_redirect(
    wired_mspan buf, usz* at, const moqctl_redirect* red) {
  usz body = *at + MOQCTL_DETAIL_HDR_MAX;
  usz end  = body;
  if (!moqctl_redirect_put(buf, &end, red)) {
    return 0;
  }
  return moqctl_detail_head_move(buf, at, body, end - body);
}

/* UNSUPPORTED_PROPERTY rides only with UNSUPPORTED_EXTENSION (9.4.2.2). */
static usz moqctl_detail_unsupp_n(const moqctl_request_error* m) {
  return m->error_code == MOQCTL_ERR_UNSUPPORTED_EXTENSION ? m->n_unsupported
                                                           : 0;
}

static int moqctl_details_put_unsupp(
    wired_mspan buf, usz* at, u64* prev, const moqctl_request_error* m) {
  moqkvp kv = {0};
  kv.type   = MOQCTL_DETAIL_UNSUPPORTED_PROPERTY;
  for (usz i = 0; i < moqctl_detail_unsupp_n(m); i++) {
    kv.num = m->unsupported[i];
    if (!moqkvp_put(buf, at, prev, &kv)) {
      return 0;
    }
  }
  return 1;
}

/* At most one REDIRECT (9.4.2: no repeats), then one UNSUPPORTED_PROPERTY
 * per Type: ascending Types, so the Deltas never go back. */
static int moqctl_details_put(
    wired_mspan buf, usz* at, const moqctl_request_error* m) {
  u64 prev = (u64)(m->has_redirect != 0); /* REDIRECT is Type 1 */
  if (m->has_redirect && !moqctl_detail_put_redirect(buf, at, &m->redirect)) {
    return 0;
  }
  return moqctl_details_put_unsupp(buf, at, &prev, m);
}

int moqctl_request_error_encode23(
    wired_mspan buf, usz* off, const moqctl_request_error* m) {
  usz at = *off;
  if (!moqctl_request_error_encode_codes_reason(buf, &at, m)) {
    return 0;
  }
  if (!moqctl_details_put(buf, &at, m)) {
    return 0;
  }
  *off = at;
  return 1;
}
