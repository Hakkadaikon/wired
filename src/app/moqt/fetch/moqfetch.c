#include "app/moqt/fetch/moqfetch_impl.h"

static int moqfetch_take_range(wired_span b, usz* at, moqfetch_fetch* m);
static int moqfetch_take_standalone(wired_span b, usz* at, moqfetch_fetch* m);
static int moqfetch_take_joining(wired_span b, usz* at, moqfetch_fetch* m);
static int moqfetch_take_badtype(wired_span b, usz* at, moqfetch_fetch* m);
static usz moqfetch_variant(u64 fetch_type);
static int moqfetch_take_head(wired_span b, usz* at, moqfetch_fetch* m);
static int moqfetch_put_standalone(
    wired_mspan b, usz* at, const moqfetch_fetch* m);
static int moqfetch_put_joining(
    wired_mspan b, usz* at, const moqfetch_fetch* m);
static int moqfetch_put_badtype(
    wired_mspan b, usz* at, const moqfetch_fetch* m);
static int moqfetch_put_head(wired_mspan b, usz* at, const moqfetch_fetch* m);

/* Every helper returns MOQCTL_OK / INSUFFICIENT / VIOLATION (takes) or
 * 1 / 0 (puts); multi-field layouts run as step tables so no function
 * chains more than two fallible calls (CCN <= 3). */

/* ===== FETCH (draft-ietf-moq-transport-19 10.12) ===== */

/* 10.12.1: Track Namespace, Track Name, Start Location, End Location. */
static int moqfetch_take_range(wired_span b, usz* at, moqfetch_fetch* m) {
  int r = moqctl_loc_take(b, at, &m->start);
  if (r != MOQCTL_OK) {
    return r;
  }
  return moqctl_loc_take(b, at, &m->end);
}

static int moqfetch_take_standalone(wired_span b, usz* at, moqfetch_fetch* m) {
  int r = moqctl_ftn_take(b, at, &m->track);
  if (r != MOQCTL_OK) {
    return r;
  }
  return moqfetch_take_range(b, at, m);
}

/* 10.12.2: Joining Request ID, Joining Start. */
static int moqfetch_take_joining(wired_span b, usz* at, moqfetch_fetch* m) {
  if (!moqvi_take(b, at, &m->joining_request_id)) {
    return MOQCTL_INSUFFICIENT;
  }
  if (!moqvi_take(b, at, &m->joining_start)) {
    return MOQCTL_INSUFFICIENT;
  }
  return MOQCTL_OK;
}

/* 10.12: "a Fetch Type other than 0x1, 0x2 or 0x3 MUST close the session
 * with a PROTOCOL_VIOLATION". */
static int moqfetch_take_badtype(wired_span b, usz* at, moqfetch_fetch* m) {
  (void)b, (void)at, (void)m;
  return MOQCTL_VIOLATION;
}

static const moqfetch_variant_take_fn MOQFETCH_VARIANT_TAKE[4] = {
    moqfetch_take_badtype, moqfetch_take_standalone, moqfetch_take_joining,
    moqfetch_take_joining};

/* Table index of a Fetch Type: 1..3, or 0 for any invalid value. */
static usz moqfetch_variant(u64 fetch_type) {
  return fetch_type <= MOQFETCH_ABSOLUTE_JOINING ? (usz)fetch_type : 0;
}

static int moqfetch_take_head(wired_span b, usz* at, moqfetch_fetch* m) {
  if (!moqvi_take(b, at, &m->request_id)) {
    return MOQCTL_INSUFFICIENT;
  }
  if (!moqvi_take(b, at, &m->fetch_type)) {
    return MOQCTL_INSUFFICIENT;
  }
  return MOQFETCH_VARIANT_TAKE[moqfetch_variant(m->fetch_type)](b, at, m);
}

int moqfetch_fetch_take(int ver, wired_span body, moqfetch_fetch* out) {
  usz at = 0;
  int r  = moqfetch_take_head(body, &at, out);
  if (r == MOQCTL_OK) {
    r = moqctl_params_take(ver, body, &at, MOQCTL_PCTX_FETCH, &out->params);
  }
  return moqctl_body_end(r, at, body);
}

static int moqfetch_put_standalone(
    wired_mspan b, usz* at, const moqfetch_fetch* m) {
  if (!moqctl_ftn_put(b, at, &m->track)) {
    return 0;
  }
  if (!moqctl_loc_put(b, at, m->start)) {
    return 0;
  }
  return moqctl_loc_put(b, at, m->end);
}

static int moqfetch_put_joining(
    wired_mspan b, usz* at, const moqfetch_fetch* m) {
  if (!moqvi_put(b, at, m->joining_request_id)) {
    return 0;
  }
  return moqvi_put(b, at, m->joining_start);
}

static int moqfetch_put_badtype(
    wired_mspan b, usz* at, const moqfetch_fetch* m) {
  (void)b, (void)at, (void)m;
  return 0;
}

static const moqfetch_variant_put_fn MOQFETCH_VARIANT_PUT[4] = {
    moqfetch_put_badtype, moqfetch_put_standalone, moqfetch_put_joining,
    moqfetch_put_joining};

static int moqfetch_put_head(wired_mspan b, usz* at, const moqfetch_fetch* m) {
  if (!moqvi_put(b, at, m->request_id)) {
    return 0;
  }
  return moqvi_put(b, at, m->fetch_type);
}

int moqfetch_fetch_encode(wired_mspan buf, usz* off, const moqfetch_fetch* m) {
  if (!moqfetch_put_head(buf, off, m)) {
    return 0;
  }
  if (!MOQFETCH_VARIANT_PUT[moqfetch_variant(m->fetch_type)](buf, off, m)) {
    return 0;
  }
  return moqctl_params_put(buf, off, &m->params);
}
