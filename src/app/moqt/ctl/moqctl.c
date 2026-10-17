#include "app/moqt/ctl/moqctl_impl.h"

static u64 moqctl_code_row_pick(const moqctl_code_row* r, int ver);
static u64 moqctl_code_for(
    const moqctl_code_row* rows, usz n, int ver, u64 code);

/* Every take/put in this file returns MOQCTL_OK/INSUFFICIENT/
 * VIOLATION (or 1/0 for encode). To keep CCN<=3, no function chains more
 * than two fallible steps directly: a third step is always pushed into a
 * helper, so each function has at most 2 branches of its own plus loop
 * overhead. */

/* ===== grease / unknown-error normalization (SS17.6) ===== */

int moqctl_is_grease(u64 v) {
  if (v < 0x9D) return 0;
  return (v - 0x9D) % 0x7f == 0;
}

int moqctl_u64_in(const u64* list, usz n, u64 v) {
  for (usz i = 0; i < n; i++)
    if (list[i] == v) return 1;
  return 0;
}

static const u64 MOQCTL_KNOWN_ERRS[] = {
    MOQCTL_ERR_INTERNAL_ERROR, MOQCTL_ERR_UNAUTHORIZED,
    MOQCTL_ERR_NOT_SUPPORTED,  MOQCTL_ERR_GOING_AWAY,
    MOQCTL_ERR_DOES_NOT_EXIST, MOQCTL_ERR_INVALID_RANGE,
    MOQCTL_ERR_UNINTERESTED,   MOQCTL_ERR_INVALID_FILTER,
    MOQCTL_ERR_REDIRECT,       MOQCTL_ERR_MALFORMED_AUTH_TOKEN};

u64 moqctl_known_request_error(u64 code) {
  if (moqctl_u64_in(MOQCTL_KNOWN_ERRS, MOQCTL_KNOWN_ERRS_N, code)) return code;
  return MOQCTL_ERR_INTERNAL_ERROR;
}

static const u64 MOQCTL_KNOWN_DONE[] = {
    MOQCTL_DONE_INTERNAL_ERROR, MOQCTL_DONE_TRACK_ENDED, MOQCTL_DONE_GOING_AWAY,
    MOQCTL_DONE_UPDATE_FAILED};

u64 moqctl_known_publish_done(u64 code) {
  if (moqctl_u64_in(MOQCTL_KNOWN_DONE, MOQCTL_KNOWN_DONE_N, code)) return code;
  return MOQCTL_DONE_INTERNAL_ERROR;
}

static const moqctl_code_row MOQCTL_ERR_ROWS[] = {
    /* 19/22 allow several subscriptions per Track (19 SS5.1): no
     * specific code is left. */
    {MOQCTL_ERR_DUPLICATE_SUBSCRIPTION, MOQVER_CAP_DUP_SUBSCRIPTION,
     MOQCTL_ERR_INTERNAL_ERROR},
    /* 18 has no filter aggregation: filters too costly to aggregate is an
     * excess of load. */
    {MOQCTL_ERR_CONFLICTING_FILTERS, MOQVER_CAP_RANGE_FILTERS,
     MOQCTL_ERR_EXCESSIVE_LOAD},
    /* 18 SS5.1.2: an unsatisfiable filter is INVALID_RANGE. */
    {MOQCTL_ERR_INVALID_FILTER, MOQVER_CAP_RANGE_FILTERS,
     MOQCTL_ERR_INVALID_RANGE},
};

static const moqctl_code_row MOQCTL_DONE_ROWS[] = {
    /* 22 SS3.3.1: a subscription no longer ends at its filter's end; the
     * remaining "publisher is done" status is TRACK_ENDED. */
    {MOQCTL_DONE_SUBSCRIPTION_ENDED, MOQVER_CAP_SUBSCRIPTION_ENDED,
     MOQCTL_DONE_TRACK_ENDED},
};

static u64 moqctl_code_row_pick(const moqctl_code_row* r, int ver) {
  return (moqver_caps(ver) & r->cap) ? r->code : r->alt;
}

static u64 moqctl_code_for(
    const moqctl_code_row* rows, usz n, int ver, u64 code) {
  for (usz i = 0; i < n; i++)
    if (rows[i].code == code) return moqctl_code_row_pick(&rows[i], ver);
  return code;
}

u64 moqctl_request_error_for(int ver, u64 code) {
  return moqctl_code_for(
      MOQCTL_ERR_ROWS, sizeof MOQCTL_ERR_ROWS / sizeof MOQCTL_ERR_ROWS[0], ver,
      code);
}

u64 moqctl_publish_done_for(int ver, u64 code) {
  return moqctl_code_for(
      MOQCTL_DONE_ROWS, sizeof MOQCTL_DONE_ROWS / sizeof MOQCTL_DONE_ROWS[0],
      ver, code);
}

/* ===== Location (SS1.4.2) ===== */

int moqctl_loc_less(moqctl_loc a, moqctl_loc b) {
  if (a.group != b.group) return a.group < b.group;
  return a.object < b.object;
}

int moqctl_loc_take(wired_span buf, usz* off, moqctl_loc* out) {
  usz at = *off;
  if (!moqvi_take(buf, &at, &out->group)) return MOQCTL_INSUFFICIENT;
  if (!moqvi_take(buf, &at, &out->object)) return MOQCTL_INSUFFICIENT;
  *off = at;
  return MOQCTL_OK;
}

int moqctl_loc_put(wired_mspan buf, usz* off, moqctl_loc loc) {
  usz at = *off;
  if (!moqvi_put(buf, &at, loc.group)) return 0;
  if (!moqvi_put(buf, &at, loc.object)) return 0;
  *off = at;
  return 1;
}
