#include "app/moqt/ctl/moqctl.h"

#include "app/moqt/fetch/moqfetch.h"
#include "app/moqt/kvp/moqkvp.h"
#include "app/moqt/ns/moqns.h"
#include "app/moqt/tstat/moqtstat.h"
#include "app/moqt/ver/moqver.h"
#include "app/moqt/vi/moqvi.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"

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

static int moqctl_u64_in(const u64* list, usz n, u64 v) {
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
#define MOQCTL_KNOWN_ERRS_N (sizeof MOQCTL_KNOWN_ERRS / sizeof(u64))

u64 moqctl_known_request_error(u64 code) {
  if (moqctl_u64_in(MOQCTL_KNOWN_ERRS, MOQCTL_KNOWN_ERRS_N, code)) return code;
  return MOQCTL_ERR_INTERNAL_ERROR;
}

static const u64 MOQCTL_KNOWN_DONE[] = {
    MOQCTL_DONE_INTERNAL_ERROR, MOQCTL_DONE_TRACK_ENDED, MOQCTL_DONE_GOING_AWAY,
    MOQCTL_DONE_UPDATE_FAILED};
#define MOQCTL_KNOWN_DONE_N (sizeof MOQCTL_KNOWN_DONE / sizeof(u64))

u64 moqctl_known_publish_done(u64 code) {
  if (moqctl_u64_in(MOQCTL_KNOWN_DONE, MOQCTL_KNOWN_DONE_N, code)) return code;
  return MOQCTL_DONE_INTERNAL_ERROR;
}

/* Send-side code rows: code exists in a draft whose caps include cap;
 * elsewhere alt, that draft's nearest defined code, is sent. */
typedef struct {
  u64 code;
  u32 cap;
  u64 alt;
} moqctl_code_row;

static const moqctl_code_row MOQCTL_ERR_ROWS[] = {
    /* 19/22 allow several subscriptions per Track (19 SS5.1): no
     * specific code is left. */
    {MOQCTL_ERR_DUPLICATE_SUBSCRIPTION, MOQVER_CAP_DUP_SUBSCRIPTION,
     MOQCTL_ERR_INTERNAL_ERROR},
    /* 22 has no Joining FETCH (SS12.3): the named request does not exist. */
    {MOQCTL_ERR_INVALID_JOINING_REQUEST_ID, MOQVER_CAP_JOINING_FETCH,
     MOQCTL_ERR_DOES_NOT_EXIST},
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

/* ===== Location Filter (SS9.3.1) ===== */

static const u64 MOQCTL_LOCFILTER_TYPES[] = {
    MOQCTL_FILTER_NEXT_GROUP, MOQCTL_FILTER_LARGEST, MOQCTL_FILTER_ABS_START,
    MOQCTL_FILTER_ABS_RANGE};
#define MOQCTL_LOCFILTER_TYPES_N (sizeof MOQCTL_LOCFILTER_TYPES / sizeof(u64))

static int moqctl_locfilter_needs_start(u64 t) {
  return t == MOQCTL_FILTER_ABS_START || t == MOQCTL_FILTER_ABS_RANGE;
}

/* Reads End Group Delta and range-checks it; only called once type ==
 * ABS_RANGE and Start is already filled in. */
static int moqctl_locfilter_take_end_value(
    wired_span buf, usz* at, moqctl_locfilter* out) {
  if (!moqvi_take(buf, at, &out->end_group_delta)) return MOQCTL_INSUFFICIENT;
  u64 end;
  return u64_add_ok(out->start.group, out->end_group_delta, &end)
             ? MOQCTL_OK
             : MOQCTL_VIOLATION;
}

static int moqctl_locfilter_take_end(
    wired_span buf, usz* at, moqctl_locfilter* out) {
  if (out->type != MOQCTL_FILTER_ABS_RANGE) return MOQCTL_OK;
  return moqctl_locfilter_take_end_value(buf, at, out);
}

static int moqctl_locfilter_take_start_then_end(
    wired_span buf, usz* at, moqctl_locfilter* out) {
  if (moqctl_loc_take(buf, at, &out->start) != MOQCTL_OK)
    return MOQCTL_INSUFFICIENT;
  return moqctl_locfilter_take_end(buf, at, out);
}

static int moqctl_locfilter_take_range(
    wired_span buf, usz* at, moqctl_locfilter* out) {
  if (!moqctl_locfilter_needs_start(out->type)) return MOQCTL_OK;
  return moqctl_locfilter_take_start_then_end(buf, at, out);
}

static int moqctl_locfilter_take_type(
    wired_span buf, usz* at, moqctl_locfilter* out) {
  if (!moqvi_take(buf, at, &out->type)) return MOQCTL_INSUFFICIENT;
  if (!moqctl_u64_in(
          MOQCTL_LOCFILTER_TYPES, MOQCTL_LOCFILTER_TYPES_N, out->type))
    return MOQCTL_VIOLATION;
  return MOQCTL_OK;
}

int moqctl_locfilter_take(wired_span buf, usz* off, moqctl_locfilter* out) {
  usz at = *off;
  int r;
  *out = (moqctl_locfilter){0};
  r    = moqctl_locfilter_take_type(buf, &at, out);
  if (r != MOQCTL_OK) return r;
  r = moqctl_locfilter_take_range(buf, &at, out);
  if (r != MOQCTL_OK) return r;
  *off = at;
  return MOQCTL_OK;
}

static int moqctl_locfilter_put_end(
    wired_mspan buf, usz* at, const moqctl_locfilter* f) {
  if (f->type != MOQCTL_FILTER_ABS_RANGE) return 1;
  return moqvi_put(buf, at, f->end_group_delta);
}

static int moqctl_locfilter_put_start_then_end(
    wired_mspan buf, usz* at, const moqctl_locfilter* f) {
  if (!moqctl_loc_put(buf, at, f->start)) return 0;
  return moqctl_locfilter_put_end(buf, at, f);
}

static int moqctl_locfilter_put_range(
    wired_mspan buf, usz* at, const moqctl_locfilter* f) {
  if (!moqctl_locfilter_needs_start(f->type)) return 1;
  return moqctl_locfilter_put_start_then_end(buf, at, f);
}

int moqctl_locfilter_put(wired_mspan buf, usz* off, const moqctl_locfilter* f) {
  usz at = *off;
  if (!moqvi_put(buf, &at, f->type)) return 0;
  if (!moqctl_locfilter_put_range(buf, &at, f)) return 0;
  *off = at;
  return 1;
}

/* ===== Version-neutral range model (moqctl_rangeloc) =====
 * Mirrors tasks/fv/moqt/Moqt/Filter.lean's SK/EK/Rng field-for-field. */

/* End Group Delta, resolved to an absolute end_group; overflow of
 * start_group+delta past 2^64-1 -> VIOLATION (shared by d19 type 4 and
 * d22 types 3/4). */
static int moqctl_rangeloc_take_end_group(
    wired_span buf, usz* at, u64 start_group, u64* end_group) {
  u64 delta;
  if (!moqvi_take(buf, at, &delta)) return MOQCTL_INSUFFICIENT;
  return u64_add_ok(start_group, delta, end_group) ? MOQCTL_OK
                                                   : MOQCTL_VIOLATION;
}

/* ----- draft-19 (SS5.1.2/SS10.2.9): type 0x1..0x4 -----
 * One function per type, dispatched by a type-indexed table so no
 * function carries more than its own type's branches (CCN). */

static int moqctl_rangeloc19_next_group(moqctl_rangeloc* out) {
  out->sk = MOQCTL_RSK_REL_GROUP; /* n = 0 */
  out->ek = MOQCTL_REK_UNBOUNDED;
  return MOQCTL_OK;
}

static int moqctl_rangeloc19_largest(moqctl_rangeloc* out) {
  out->sk = MOQCTL_RSK_NEXT_OBJ;
  out->ek = MOQCTL_REK_UNBOUNDED;
  return MOQCTL_OK;
}

static int moqctl_rangeloc19_abs_start(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  out->sk = MOQCTL_RSK_ABS;
  out->ek = MOQCTL_REK_UNBOUNDED;
  if (!moqvi_take(buf, at, &out->start_group)) return MOQCTL_INSUFFICIENT;
  if (!moqvi_take(buf, at, &out->start_object)) return MOQCTL_INSUFFICIENT;
  return MOQCTL_OK;
}

static int moqctl_rangeloc19_abs_range(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  int r = moqctl_rangeloc19_abs_start(buf, at, out);
  if (r != MOQCTL_OK) return r;
  out->ek = MOQCTL_REK_GROUP;
  return moqctl_rangeloc_take_end_group(
      buf, at, out->start_group, &out->end_group);
}

typedef int (*moqctl_rangeloc19_fn)(wired_span, usz*, moqctl_rangeloc*);

static int moqctl_rangeloc19_next_group_fn(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  (void)buf;
  (void)at;
  return moqctl_rangeloc19_next_group(out);
}

static int moqctl_rangeloc19_largest_fn(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  (void)buf;
  (void)at;
  return moqctl_rangeloc19_largest(out);
}

/* Index 0 unused (type 0 is not a valid d19 Filter Type); indices 1..4
 * are MOQCTL_FILTER_NEXT_GROUP..MOQCTL_FILTER_ABS_RANGE. */
static const moqctl_rangeloc19_fn MOQCTL_RANGELOC19_FNS[5] = {
    0, moqctl_rangeloc19_next_group_fn, moqctl_rangeloc19_largest_fn,
    moqctl_rangeloc19_abs_start, moqctl_rangeloc19_abs_range};
#define MOQCTL_RANGELOC19_FNS_N \
  (sizeof MOQCTL_RANGELOC19_FNS / sizeof(moqctl_rangeloc19_fn))

static int moqctl_rangeloc19_body(
    u64 type, wired_span buf, usz* at, moqctl_rangeloc* out) {
  if (type == 0 || type >= MOQCTL_RANGELOC19_FNS_N) return MOQCTL_VIOLATION;
  return MOQCTL_RANGELOC19_FNS[type](buf, at, out);
}

int moqctl_rangeloc19_take(wired_span buf, usz* off, moqctl_rangeloc* out) {
  usz at = *off;
  u64 type;
  int r;
  *out = (moqctl_rangeloc){0};
  if (!moqvi_take(buf, &at, &type)) return MOQCTL_INSUFFICIENT;
  r = moqctl_rangeloc19_body(type, buf, &at, out);
  if (r != MOQCTL_OK) return r;
  *off = at;
  return MOQCTL_OK;
}

static u64 moqctl_rangeloc19_wire_type_abs(const moqctl_rangeloc* r) {
  return r->ek == MOQCTL_REK_GROUP ? MOQCTL_FILTER_ABS_RANGE
                                   : MOQCTL_FILTER_ABS_START;
}

static u64 moqctl_rangeloc19_wire_type(const moqctl_rangeloc* r) {
  if (r->sk == MOQCTL_RSK_REL_GROUP) return MOQCTL_FILTER_NEXT_GROUP;
  if (r->sk == MOQCTL_RSK_NEXT_OBJ) return MOQCTL_FILTER_LARGEST;
  return moqctl_rangeloc19_wire_type_abs(r);
}

static int moqctl_rangeloc19_put_end(
    wired_mspan buf, usz* at, const moqctl_rangeloc* r) {
  if (r->ek != MOQCTL_REK_GROUP) return 1;
  return moqvi_put(buf, at, r->end_group - r->start_group);
}

static int moqctl_rangeloc19_put_start(
    wired_mspan buf, usz* at, const moqctl_rangeloc* r) {
  if (!moqvi_put(buf, at, r->start_group)) return 0;
  return moqvi_put(buf, at, r->start_object);
}

static int moqctl_rangeloc19_put_abs(
    wired_mspan buf, usz* at, const moqctl_rangeloc* r) {
  if (!moqctl_rangeloc19_put_start(buf, at, r)) return 0;
  return moqctl_rangeloc19_put_end(buf, at, r);
}

static int moqctl_rangeloc19_put_fields(
    wired_mspan buf, usz* at, const moqctl_rangeloc* r) {
  if (r->sk != MOQCTL_RSK_ABS) return 1; /* no fields for this type */
  return moqctl_rangeloc19_put_abs(buf, at, r);
}

int moqctl_rangeloc19_put(wired_mspan buf, usz* off, const moqctl_rangeloc* r) {
  usz at = *off;
  if (!moqvi_put(buf, &at, moqctl_rangeloc19_wire_type(r))) return 0;
  if (!moqctl_rangeloc19_put_fields(buf, &at, r)) return 0;
  *off = at;
  return 1;
}

/* ----- draft-22 (SS9.20.9): type 0x00..0x05 -----
 * Same one-function-per-type + table-dispatch shape as d19 above. */

static int moqctl_rangeloc22_take_start(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  out->sk = MOQCTL_RSK_ABS;
  if (!moqvi_take(buf, at, &out->start_group)) return MOQCTL_INSUFFICIENT;
  return moqvi_take(buf, at, &out->start_object) ? MOQCTL_OK
                                                 : MOQCTL_INSUFFICIENT;
}

static int moqctl_rangeloc22_abs_start_group_end(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  int r = moqctl_rangeloc22_take_start(buf, at, out);
  if (r != MOQCTL_OK) return r;
  out->ek = MOQCTL_REK_GROUP;
  return moqctl_rangeloc_take_end_group(
      buf, at, out->start_group, &out->end_group);
}

static int moqctl_rangeloc22_abs_range(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  int r = moqctl_rangeloc22_abs_start_group_end(buf, at, out);
  if (r != MOQCTL_OK) return r;
  out->ek = MOQCTL_REK_OBJ;
  return moqvi_take(buf, at, &out->end_object) ? MOQCTL_OK
                                               : MOQCTL_INSUFFICIENT;
}

static int moqctl_rangeloc22_relative_start(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  out->sk = MOQCTL_RSK_REL_GROUP;
  out->ek = MOQCTL_REK_UNBOUNDED;
  return moqvi_take(buf, at, &out->start_group) ? MOQCTL_OK
                                                : MOQCTL_INSUFFICIENT;
}

static int moqctl_rangeloc22_abs_start(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  int r = moqctl_rangeloc22_take_start(buf, at, out);
  if (r != MOQCTL_OK) return r;
  out->ek = MOQCTL_REK_UNBOUNDED;
  return MOQCTL_OK;
}

static int moqctl_rangeloc22_next_object_fn(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  (void)buf;
  (void)at;
  out->sk = MOQCTL_RSK_NEXT_OBJ;
  out->ek = MOQCTL_REK_UNBOUNDED;
  return MOQCTL_OK;
}

typedef int (*moqctl_rangeloc22_fn)(wired_span, usz*, moqctl_rangeloc*);

/* Index 0 unused (type 0 is "no filter", handled before dispatch);
 * indices 1..5 are Relative Start .. Next Object. */
static const moqctl_rangeloc22_fn MOQCTL_RANGELOC22_FNS[6] = {
    0,
    moqctl_rangeloc22_relative_start,
    moqctl_rangeloc22_abs_start,
    moqctl_rangeloc22_abs_start_group_end,
    moqctl_rangeloc22_abs_range,
    moqctl_rangeloc22_next_object_fn};
#define MOQCTL_RANGELOC22_FNS_N \
  (sizeof MOQCTL_RANGELOC22_FNS / sizeof(moqctl_rangeloc22_fn))

static int moqctl_rangeloc22_body(
    u64 type, wired_span buf, usz* at, moqctl_rangeloc* out) {
  if (type == 0 || type >= MOQCTL_RANGELOC22_FNS_N) return MOQCTL_VIOLATION;
  return MOQCTL_RANGELOC22_FNS[type](buf, at, out);
}

/* type == 0x0 ("None") already consumed from *at; everything else goes
 * through moqctl_rangeloc22_body. */
static int moqctl_rangeloc22_take_rest(
    u64 type, wired_span buf, usz* at, int* has_filter, moqctl_rangeloc* out) {
  int r;
  if (type == 0x0) {
    *has_filter = 0;
    return MOQCTL_OK;
  }
  r = moqctl_rangeloc22_body(type, buf, at, out);
  if (r != MOQCTL_OK) return r;
  *has_filter = 1;
  return MOQCTL_OK;
}

int moqctl_rangeloc22_take(
    wired_span buf, usz* off, int* has_filter, moqctl_rangeloc* out) {
  usz at = *off;
  u64 type;
  int r;
  *out = (moqctl_rangeloc){0};
  if (!moqvi_take(buf, &at, &type)) return MOQCTL_INSUFFICIENT;
  r = moqctl_rangeloc22_take_rest(type, buf, &at, has_filter, out);
  if (r != MOQCTL_OK) return r;
  *off = at;
  return MOQCTL_OK;
}

static u64 moqctl_rangeloc22_wire_type_abs(const moqctl_rangeloc* r) {
  if (r->ek == MOQCTL_REK_UNBOUNDED) return 0x2;
  return r->ek == MOQCTL_REK_GROUP ? 0x3 : 0x4;
}

static u64 moqctl_rangeloc22_wire_type(const moqctl_rangeloc* r) {
  if (r->sk == MOQCTL_RSK_REL_GROUP) return 0x1;
  if (r->sk == MOQCTL_RSK_NEXT_OBJ) return 0x5;
  return moqctl_rangeloc22_wire_type_abs(r);
}

static int moqctl_rangeloc22_put_end_object(
    wired_mspan buf, usz* at, const moqctl_rangeloc* r) {
  if (r->ek != MOQCTL_REK_OBJ) return 1;
  return moqvi_put(buf, at, r->end_object);
}

static int moqctl_rangeloc22_put_end(
    wired_mspan buf, usz* at, const moqctl_rangeloc* r) {
  if (r->ek == MOQCTL_REK_UNBOUNDED) return 1;
  if (!moqvi_put(buf, at, r->end_group - r->start_group)) return 0;
  return moqctl_rangeloc22_put_end_object(buf, at, r);
}

static int moqctl_rangeloc22_put_abs(
    wired_mspan buf, usz* at, const moqctl_rangeloc* r) {
  if (!moqvi_put(buf, at, r->start_group)) return 0;
  if (!moqvi_put(buf, at, r->start_object)) return 0;
  return moqctl_rangeloc22_put_end(buf, at, r);
}

static int moqctl_rangeloc22_put_body(
    wired_mspan buf, usz* at, const moqctl_rangeloc* r) {
  if (r->sk == MOQCTL_RSK_REL_GROUP) return moqvi_put(buf, at, r->start_group);
  if (r->sk == MOQCTL_RSK_ABS) return moqctl_rangeloc22_put_abs(buf, at, r);
  return 1; /* NEXT_OBJ carries no fields */
}

static int moqctl_rangeloc22_put_none(wired_mspan buf, usz* off, usz at) {
  if (!moqvi_put(buf, &at, 0x0)) return 0;
  *off = at;
  return 1;
}

static int moqctl_rangeloc22_put_present(
    wired_mspan buf, usz* off, const moqctl_rangeloc* r) {
  usz at = *off;
  if (!moqvi_put(buf, &at, moqctl_rangeloc22_wire_type(r))) return 0;
  if (!moqctl_rangeloc22_put_body(buf, &at, r)) return 0;
  *off = at;
  return 1;
}

int moqctl_rangeloc22_put(
    wired_mspan buf, usz* off, int has_filter, const moqctl_rangeloc* r) {
  if (!has_filter) return moqctl_rangeloc22_put_none(buf, off, *off);
  return moqctl_rangeloc22_put_present(buf, off, r);
}

/* ----- Named violation predicates (Q-04a/Q-04b) ----- */

int moqctl_rangeloc_q04a_violation(const moqctl_rangeloc* r) {
  if (r->ek != MOQCTL_REK_OBJ) return 0;
  if (r->end_group != r->start_group) return 0;
  return r->end_object < r->start_object;
}

int moqctl_rangeloc_q04b_violation(const moqctl_rangeloc* r) {
  return r->sk == MOQCTL_RSK_NEXT_OBJ;
}

/* ===== Track Namespace / Full Track Name (SS1.5) ===== */

/* 1 if a varint was actually consumed (buf had room), 0 if truncated. */
static int moqctl_span_take_len(wired_span buf, usz* at, u64* len) {
  return moqvi_take(buf, at, len);
}

static int moqctl_bytes_take(
    wired_span buf, usz* at, u64 len, wired_span* out) {
  if (buf.n - *at < len) return MOQCTL_INSUFFICIENT;
  *out = wired_span_of(buf.p + *at, (usz)len);
  *at += (usz)len;
  return MOQCTL_OK;
}

static int moqctl_ns_field_take(wired_span buf, usz* at, wired_span* field) {
  u64 len;
  if (!moqctl_span_take_len(buf, at, &len)) return MOQCTL_INSUFFICIENT;
  if (len == 0) return MOQCTL_VIOLATION;
  return moqctl_bytes_take(buf, at, len, field);
}

static int moqctl_ns_take_fields(wired_span buf, usz* at, moqctl_ns* ns) {
  for (usz i = 0; i < ns->n; i++) {
    int r = moqctl_ns_field_take(buf, at, &ns->fields[i]);
    if (r != MOQCTL_OK) return r;
  }
  return MOQCTL_OK;
}

static int moqctl_ns_take_count(wired_span buf, usz* at, moqctl_ns* ns) {
  u64 count;
  if (!moqvi_take(buf, at, &count)) return MOQCTL_INSUFFICIENT;
  if (count > MOQCTL_MAX_NS_FIELDS) return MOQCTL_VIOLATION;
  ns->n = (usz)count;
  return MOQCTL_OK;
}

/* SS2.4.1: "If an endpoint receives a Track Namespace ... exceeding 4,096
 * bytes, it MUST close the session with a PROTOCOL_VIOLATION" (length =
 * sum of the field lengths). Applies to every Track Namespace this file
 * decodes: FTN, redirect, TRACK_NAMESPACE_PREFIX, and moqctl_ns_take. */
static int moqctl_ns_bound(const moqctl_ns* ns) {
  return moqctl_ns_bytelen(ns) > MOQCTL_MAX_FTN_LEN ? MOQCTL_VIOLATION
                                                    : MOQCTL_OK;
}

static int moqctl_ns_take_fields_bound(wired_span buf, usz* at, moqctl_ns* ns) {
  int r = moqctl_ns_take_fields(buf, at, ns);
  if (r != MOQCTL_OK) return r;
  return moqctl_ns_bound(ns);
}

static int moqctl_ns_take_at(wired_span buf, usz* at, moqctl_ns* ns) {
  int r = moqctl_ns_take_count(buf, at, ns);
  if (r != MOQCTL_OK) return r;
  return moqctl_ns_take_fields_bound(buf, at, ns);
}

int moqctl_ns_take(wired_span buf, usz* off, moqctl_ns* out) {
  usz at = *off;
  int r  = moqctl_ns_take_at(buf, &at, out);
  if (r != MOQCTL_OK) return r;
  *off = at;
  return MOQCTL_OK;
}

usz moqctl_ns_bytelen(const moqctl_ns* ns) {
  usz total = 0;
  for (usz i = 0; i < ns->n; i++) total += ns->fields[i].n;
  return total;
}

int moqctl_name_take(wired_span buf, usz* at, wired_span* name) {
  u64 len;
  if (!moqctl_span_take_len(buf, at, &len)) return MOQCTL_INSUFFICIENT;
  return moqctl_bytes_take(buf, at, len, name);
}

static int moqctl_ftn_bound_check(const moqctl_ftn* f) {
  if (moqctl_ns_bytelen(&f->ns) + f->name.n > MOQCTL_MAX_FTN_LEN)
    return MOQCTL_VIOLATION;
  return MOQCTL_OK;
}

static int moqctl_ftn_take_ns_then_name(
    wired_span buf, usz* at, moqctl_ftn* out) {
  int r = moqctl_name_take(buf, at, &out->name);
  if (r != MOQCTL_OK) return r;
  return moqctl_ftn_bound_check(out);
}

int moqctl_ftn_take(wired_span buf, usz* off, moqctl_ftn* out) {
  usz at = *off;
  int r  = moqctl_ns_take_at(buf, &at, &out->ns);
  if (r != MOQCTL_OK) return r;
  r = moqctl_ftn_take_ns_then_name(buf, &at, out);
  if (r != MOQCTL_OK) return r;
  *off = at;
  return MOQCTL_OK;
}

static int moqctl_ns_field_put(wired_mspan buf, usz* at, wired_span field) {
  if (!moqvi_put(buf, at, field.n)) return 0;
  return bytes_put(buf, at, field);
}

static int moqctl_ns_put_fields(wired_mspan buf, usz* at, const moqctl_ns* ns) {
  for (usz i = 0; i < ns->n; i++)
    if (!moqctl_ns_field_put(buf, at, ns->fields[i])) return 0;
  return 1;
}

int moqctl_ns_put(wired_mspan buf, usz* at, const moqctl_ns* ns) {
  if (!moqvi_put(buf, at, ns->n)) return 0;
  return moqctl_ns_put_fields(buf, at, ns);
}

int moqctl_name_put(wired_mspan buf, usz* at, wired_span name) {
  if (!moqvi_put(buf, at, name.n)) return 0;
  return bytes_put(buf, at, name);
}

int moqctl_ftn_put(wired_mspan buf, usz* off, const moqctl_ftn* f) {
  usz at = *off;
  if (!moqctl_ns_put(buf, &at, &f->ns)) return 0;
  if (!moqctl_name_put(buf, &at, f->name)) return 0;
  *off = at;
  return 1;
}

static int moqctl_bytes_eq(const u8* a, const u8* b, usz n) {
  for (usz i = 0; i < n; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

static int moqctl_span_eq(wired_span a, wired_span b) {
  if (a.n != b.n) return 0;
  return moqctl_bytes_eq(a.p, b.p, a.n);
}

static int moqctl_ns_fields_eq(const moqctl_ns* a, const moqctl_ns* b) {
  for (usz i = 0; i < a->n; i++)
    if (!moqctl_span_eq(a->fields[i], b->fields[i])) return 0;
  return 1;
}

static int moqctl_ns_eq(const moqctl_ns* a, const moqctl_ns* b) {
  if (a->n != b->n) return 0;
  return moqctl_ns_fields_eq(a, b);
}

int moqctl_ftn_eq(const moqctl_ftn* a, const moqctl_ftn* b) {
  if (!moqctl_ns_eq(&a->ns, &b->ns)) return 0;
  return moqctl_span_eq(a->name, b->name);
}

/* ===== Reason Phrase (SS1.4.4) ===== */

static int moqctl_reason_take_len(wired_span buf, usz* at, u64* len) {
  if (!moqctl_span_take_len(buf, at, len)) return MOQCTL_INSUFFICIENT;
  if (*len > MOQCTL_MAX_REASON_LEN) return MOQCTL_VIOLATION;
  return MOQCTL_OK;
}

int moqctl_reason_take(wired_span buf, usz* off, moqctl_reason* out) {
  usz at = *off;
  u64 len;
  int r = moqctl_reason_take_len(buf, &at, &len);
  if (r != MOQCTL_OK) return r;
  r = moqctl_bytes_take(buf, &at, len, out);
  if (r != MOQCTL_OK) return r;
  *off = at;
  return MOQCTL_OK;
}

int moqctl_reason_put(wired_mspan buf, usz* off, moqctl_reason reason) {
  usz at = *off;
  if (!moqvi_put(buf, &at, reason.n)) return 0;
  if (!bytes_put(buf, &at, reason)) return 0;
  *off = at;
  return 1;
}

/* ===== Message Parameters (SS10.2) ===== */

/* Registry (SS10.2.x): per known Type, its encoding and, per draft
 * (indexed by MOQVER_*), the MOQCTL_PCTX_* set it may appear in -- 0 where
 * the draft does not define the Type, which then decodes like an unknown
 * one. Table-driven to keep dispatch a single lookup instead of an if/else
 * chain per type. */
typedef struct {
  u64 type;
  int enc;
  u32 ctx[MOQVER_COUNT];
  u8  lo, hi; /* allowed uint8 values; other encodings leave u8v 0 */
  u8  repeat; /* the Type MAY appear more than once (SS5.1.3) */
} moqctl_param_rule;

/* ctx sets, {draft-22, draft-19, draft-18}: each draft's "MAY appear in"
 * (22 SS9.20.x, 19 SS10.2.x, 18 SS10.2.x). draft-19 adds SUBSCRIBE_TRACKS
 * for every SUBSCRIBE parameter (19 SS10.19.1); draft-18 PUBLISH also takes
 * GROUP_ORDER, which a SUBSCRIBE_TRACKS-generated PUBLISH echoes. An
 * unqualified "REQUEST_UPDATE" covers every REQUEST_UPDATE kind.
 * RENDEZVOUS and FILL timeouts state no encoding; varint is assumed. Range
 * filters (5.1.3) and FILL_PARAMETERS (22 SS9.20.15: Number of Parameters
 * + Parameters) are kept as their raw Length-prefixed bytes. */
/* clang-format off */
static const moqctl_param_rule MOQCTL_PARAM_RULES[] = {
    /* type, enc, ctx {d22, d19, d18}, lo, hi, repeat */
    {MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT,   MOQCTL_PENC_VARINT,    {0x7C005, 0x7D009, 0x7C009}, 0, 0,   0},
    {MOQCTL_PARAM_AUTHORIZATION_TOKEN,       MOQCTL_PENC_TOKEN,     {0x7D555, 0x7D555, 0x7D555}, 0, 0,   0},
    {MOQCTL_PARAM_RENDEZVOUS_TIMEOUT,        MOQCTL_PENC_VARINT,    {0x1,     0x1001,  0x1},     0, 0,   0},
    {MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT, MOQCTL_PENC_VARINT,    {0x7C005, 0x7D009, 0x7C009}, 0, 0,   0},
    {MOQCTL_PARAM_EXPIRES,                   MOQCTL_PENC_VARINT,    {0x82A0E, 0x82A0E, 0x8000E}, 0, 0,   0},
    {MOQCTL_PARAM_LARGEST_OBJECT,            MOQCTL_PENC_LOCATION,  {0x80086, 0x80086, 0x80086}, 0, 0,   0},
    {MOQCTL_PARAM_FILL_TIMEOUT,              MOQCTL_PENC_VARINT,    {0x10,    0x10,    0x10},    0, 0,   0},
    {MOQCTL_PARAM_FORWARD,                   MOQCTL_PENC_UINT8,     {0x25005, 0x500D,  0x500D},  0, 1,   0},
    {MOQCTL_PARAM_SUBSCRIBER_PRIORITY,       MOQCTL_PENC_UINT8,     {0xC015,  0xD019,  0xC019},  0, 255, 0},
    {MOQCTL_PARAM_LOCATION_FILTER,           MOQCTL_PENC_LOCFILTER, {0x4015,  0x5009,  0x4009},  0, 0,   0},
    {MOQCTL_PARAM_GROUP_ORDER,               MOQCTL_PENC_UINT8,     {0x1015,  0x1011,  0x1D},    1, 2,   0},
    {MOQCTL_PARAM_FILL_PARAMETERS,           MOQCTL_PENC_BYTES,     {0x4001,  0,       0},       0, 0,   0},
    {MOQCTL_PARAM_SUBGROUP_FILTER,           MOQCTL_PENC_BYTES,     {0x5011,  0x5019,  0},       0, 0,   1},
    {MOQCTL_PARAM_OBJECTID_FILTER,           MOQCTL_PENC_BYTES,     {0x5011,  0x5019,  0},       0, 0,   1},
    {MOQCTL_PARAM_PRIORITY_FILTER,           MOQCTL_PENC_BYTES,     {0x5011,  0x5019,  0},       0, 0,   1},
    {MOQCTL_PARAM_OBJECT_PROPERTY_FILTER,    MOQCTL_PENC_BYTES,     {0x5011,  0x5019,  0},       0, 0,   1},
    {MOQCTL_PARAM_TRACK_PROPERTY_FILTER,     MOQCTL_PENC_BYTES,     {0x21000, 0x21000, 0},       0, 0,   1},
    {MOQCTL_PARAM_NEW_GROUP_REQUEST,         MOQCTL_PENC_VARINT,    {0x4001,  0x5009,  0x4009},  0, 0,   0},
    {MOQCTL_PARAM_TRACK_NAMESPACE_PREFIX,    MOQCTL_PENC_NS,        {0x30000, 0x30000, 0x30000}, 0, 0,   0},
    {MOQCTL_PARAM_INCLUDE_PROPERTIES,        MOQCTL_PENC_UINT8,     {0x1051,  0,       0},       0, 1,   0},
};
/* clang-format on */
#define MOQCTL_PARAM_RULE_N \
  (sizeof MOQCTL_PARAM_RULES / sizeof MOQCTL_PARAM_RULES[0])

static const moqctl_param_rule* moqctl_param_rule_for(u64 type) {
  for (usz i = 0; i < MOQCTL_PARAM_RULE_N; i++)
    if (MOQCTL_PARAM_RULES[i].type == type) return &MOQCTL_PARAM_RULES[i];
  return 0;
}

static int moqctl_param_allowed_in(
    const moqctl_param_rule* rule, int ver, u32 ctx) {
  return (rule->ctx[ver] & ctx) != 0;
}

int moqctl_param_take_uint8(wired_span buf, usz* at, u64* out) {
  if (buf.n - *at < 1) return MOQCTL_INSUFFICIENT;
  *out = buf.p[*at];
  *at += 1;
  return MOQCTL_OK;
}

static int moqctl_param_take_varint(wired_span buf, usz* at, u64* out) {
  return moqvi_take(buf, at, out) ? MOQCTL_OK : MOQCTL_INSUFFICIENT;
}

/* Value dispatch table: one function per encoding, indexed by
 * MOQCTL_PENC_*, so the caller never branches on enc itself. */
typedef int (*moqctl_param_value_fn)(wired_span, usz*, moqctl_param*);

static int moqctl_pv_uint8(wired_span buf, usz* at, moqctl_param* p) {
  return moqctl_param_take_uint8(buf, at, &p->u8v);
}
static int moqctl_pv_varint(wired_span buf, usz* at, moqctl_param* p) {
  return moqctl_param_take_varint(buf, at, &p->vi);
}
static int moqctl_pv_location(wired_span buf, usz* at, moqctl_param* p) {
  return moqctl_loc_take(buf, at, &p->loc);
}
static int moqctl_pv_bytes(wired_span buf, usz* at, moqctl_param* p) {
  u64 len;
  if (!moqctl_span_take_len(buf, at, &len)) return MOQCTL_INSUFFICIENT;
  return moqctl_bytes_take(buf, at, len, &p->bytes);
}

/* ===== AUTHORIZATION TOKEN (SS10.2.2 Figure 5) ===== */

/* Per Alias Type (index = MOQCTL_TOKEN_*): does the Token carry an Alias
 * field, and does it carry Token Type + Token Value. */
static const int MOQCTL_TOKEN_HAS_ALIAS[4] = {1, 1, 1, 0};
static const int MOQCTL_TOKEN_HAS_VALUE[4] = {0, 1, 0, 1};

static int moqctl_token_take_alias(wired_span v, usz* at, moqctl_token* t) {
  if (!MOQCTL_TOKEN_HAS_ALIAS[t->alias_type]) return MOQCTL_OK;
  if (!moqvi_take(v, at, &t->alias)) return MOQCTL_PARAMS_KVFMT;
  return MOQCTL_OK;
}

/* Token Value is the remainder of the Length-prefixed value; an Alias-only
 * shape must end exactly at the Alias. */
static int moqctl_token_at_end(wired_span v, usz at) {
  return at == v.n ? MOQCTL_OK : MOQCTL_PARAMS_KVFMT;
}

static int moqctl_token_take_value(wired_span v, usz* at, moqctl_token* t) {
  if (!MOQCTL_TOKEN_HAS_VALUE[t->alias_type])
    return moqctl_token_at_end(v, *at);
  if (!moqvi_take(v, at, &t->token_type)) return MOQCTL_PARAMS_KVFMT;
  t->value = wired_span_of(v.p + *at, v.n - *at);
  return MOQCTL_OK;
}

static int moqctl_token_take_head(wired_span v, usz* at, moqctl_token* t) {
  if (!moqvi_take(v, at, &t->alias_type)) return MOQCTL_PARAMS_KVFMT;
  if (t->alias_type > MOQCTL_TOKEN_USE_VALUE) return MOQCTL_PARAMS_KVFMT;
  return moqctl_token_take_alias(v, at, t);
}

/* v is exactly the parameter's Length bytes. "If the Token structure
 * cannot be decoded, the receiver MUST close the Session with
 * KEY_VALUE_FORMATTING_ERROR" -- surfaced as MOQCTL_PARAMS_KVFMT. */
static int moqctl_token_take(wired_span v, moqctl_token* t) {
  usz at = 0;
  int r  = moqctl_token_take_head(v, &at, t);
  if (r != MOQCTL_OK) return r;
  return moqctl_token_take_value(v, &at, t);
}

static int moqctl_pv_token(wired_span buf, usz* at, moqctl_param* p) {
  int r = moqctl_pv_bytes(buf, at, p);
  if (r != MOQCTL_OK) return r;
  return moqctl_token_take(p->bytes, &p->token);
}

/* A Location Filter must fill its Length exactly (SS5.1.2). */
static int moqctl_locfilter_exact(wired_span v, moqctl_locfilter* f) {
  usz a = 0;
  if (moqctl_locfilter_take(v, &a, f) != MOQCTL_OK) return MOQCTL_VIOLATION;
  return a == v.n ? MOQCTL_OK : MOQCTL_VIOLATION;
}

static int moqctl_pv_locfilter(wired_span buf, usz* at, moqctl_param* p) {
  int r = moqctl_pv_bytes(buf, at, p);
  if (r != MOQCTL_OK) return r;
  return moqctl_locfilter_exact(p->bytes, &p->lf);
}

static int moqctl_pv_ns(wired_span buf, usz* at, moqctl_param* p) {
  moqctl_ns ns;
  usz       start = *at;
  int       r     = moqctl_ns_take(buf, at, &ns);
  p->bytes        = wired_span_of(buf.p + start, *at - start);
  return r;
}

/* draft-22 LOCATION_FILTER (SS9.20.9): no Length prefix at all. */
static int moqctl_pv_rangeloc22(wired_span buf, usz* at, moqctl_param* p) {
  return moqctl_rangeloc22_take(buf, at, &p->has_filter, &p->rl);
}

static const moqctl_param_value_fn MOQCTL_PARAM_VALUE_FNS[8] = {
    moqctl_pv_uint8, moqctl_pv_varint,    moqctl_pv_location,
    moqctl_pv_bytes, moqctl_pv_token,     moqctl_pv_locfilter,
    moqctl_pv_ns,    moqctl_pv_rangeloc22};

static int moqctl_param_take_value(
    wired_span buf, usz* at, int enc, moqctl_param* p) {
  return MOQCTL_PARAM_VALUE_FNS[enc](buf, at, p);
}

static int moqctl_param_in_range(
    const moqctl_param_rule* rule, const moqctl_param* p) {
  if (rule->enc != MOQCTL_PENC_UINT8) return 1;
  return p->u8v >= rule->lo && p->u8v <= rule->hi;
}

/* FORWARD outside {0,1} (SS10.2.17) and GROUP_ORDER outside {1,2}
 * (SS10.2.8) MUST close the session with PROTOCOL_VIOLATION. */
static int moqctl_param_take_checked(
    wired_span buf, usz* at, const moqctl_param_rule* rule, moqctl_param* p) {
  int r = moqctl_param_take_value(buf, at, rule->enc, p);
  if (r != MOQCTL_OK) return r;
  return moqctl_param_in_range(rule, p) ? MOQCTL_OK : MOQCTL_VIOLATION;
}

static int moqctl_param_dup(const moqctl_params* out, u64 type) {
  for (usz i = 0; i < out->n; i++)
    if (out->items[i].type == type) return 1;
  return 0;
}

/* A Type already in out may come again only where its definition allows
 * repeats (SS10.2). */
static int moqctl_param_fresh(
    const moqctl_param_rule* rule, const moqctl_params* out, u64 type) {
  return rule->repeat || !moqctl_param_dup(out, type);
}

/* Unknown Type is always a VIOLATION per SS10.2 (no skip mechanism
 * exists); so is a known one outside ver's ctx or repeated. */
static int moqctl_param_admit(
    const moqctl_param_rule* rule,
    int                      ver,
    u32                      ctx,
    const moqctl_params*     out,
    u64                      t) {
  return moqctl_param_allowed_in(rule, ver, ctx) &&
         moqctl_param_fresh(rule, out, t);
}

static int moqctl_param_take_delta(
    wired_span buf, usz* at, u64 prev, moqctl_param* p) {
  u64 delta;
  if (!moqvi_take(buf, at, &delta)) return MOQCTL_INSUFFICIENT;
  return u64_add_ok(prev, delta, &p->type) ? MOQCTL_OK : MOQCTL_VIOLATION;
}

/* d22's LOCATION_FILTER is the only Type whose wire shape differs from
 * d19's (SS9.20.9, no Length, vs SS5.1.2); scopes live in the table. */
static int moqctl_param_typed_filter(const moqctl_param_rule* rule, int ver) {
  return rule->type == MOQCTL_PARAM_LOCATION_FILTER &&
         (moqver_caps(ver) & MOQVER_CAP_LOCFILTER_TYPED);
}

static void moqctl_param_rule_select(
    const moqctl_param_rule* rule, int ver, moqctl_param_rule* over) {
  *over = *rule;
  if (moqctl_param_typed_filter(rule, ver)) over->enc = MOQCTL_PENC_RANGELOC22;
}

static int moqctl_param_take_body(
    wired_span     buf,
    usz*           at,
    u32            ctx,
    int            ver,
    moqctl_params* out,
    moqctl_param*  p) {
  const moqctl_param_rule* rule = moqctl_param_rule_for(p->type);
  moqctl_param_rule        over = {0};
  if (!rule) return MOQCTL_VIOLATION;
  moqctl_param_rule_select(rule, ver, &over);
  if (!moqctl_param_admit(&over, ver, ctx, out, p->type))
    return MOQCTL_VIOLATION;
  p->enc = over.enc;
  return moqctl_param_take_checked(buf, at, &over, p);
}

static int moqctl_param_take_one(
    wired_span buf, usz* at, u32 ctx, int ver, u64 prev, moqctl_params* out) {
  moqctl_param p = {0};
  int          r = moqctl_param_take_delta(buf, at, prev, &p);
  if (r != MOQCTL_OK) return r;
  r = moqctl_param_take_body(buf, at, ctx, ver, out, &p);
  if (r != MOQCTL_OK) return r;
  out->items[out->n] = p;
  out->n++;
  return MOQCTL_OK;
}

static int moqctl_params_take_step(
    wired_span buf, usz* at, u32 ctx, int ver, u64* prev, moqctl_params* out) {
  int r;
  if (out->n >= MOQCTL_MAX_PARAMS) return MOQCTL_VIOLATION;
  r = moqctl_param_take_one(buf, at, ctx, ver, *prev, out);
  if (r != MOQCTL_OK) return r;
  *prev = out->items[out->n - 1].type;
  return MOQCTL_OK;
}

static int moqctl_params_take_loop(
    wired_span buf, usz* at, u32 ctx, int ver, u64 count, moqctl_params* out) {
  u64 prev = 0;
  for (u64 i = 0; i < count; i++) {
    int r = moqctl_params_take_step(buf, at, ctx, ver, &prev, out);
    if (r != MOQCTL_OK) return r;
  }
  return MOQCTL_OK;
}

static int moqctl_params_take_any(
    wired_span buf, usz* off, u32 ctx, int ver, moqctl_params* out) {
  usz at = *off;
  u64 count;
  int r;
  out->n = 0;
  if (!moqvi_take(buf, &at, &count)) return MOQCTL_INSUFFICIENT;
  r = moqctl_params_take_loop(buf, &at, ctx, ver, count, out);
  if (r != MOQCTL_OK) return r;
  *off = at;
  return MOQCTL_OK;
}

int moqctl_params_take(
    int ver, wired_span buf, usz* off, u32 ctx, moqctl_params* out) {
  return moqctl_params_take_any(buf, off, ctx, ver, out);
}

int moqctl_param_put_uint8(wired_mspan buf, usz* at, u64 v) {
  if (*at + 1 > buf.n) return 0;
  buf.p[*at] = (u8)v;
  *at += 1;
  return 1;
}

typedef int (*moqctl_param_put_fn)(wired_mspan, usz*, const moqctl_param*);

static int moqctl_pp_uint8(wired_mspan buf, usz* at, const moqctl_param* p) {
  return moqctl_param_put_uint8(buf, at, p->u8v);
}
static int moqctl_pp_varint(wired_mspan buf, usz* at, const moqctl_param* p) {
  return moqvi_put(buf, at, p->vi);
}
static int moqctl_pp_location(wired_mspan buf, usz* at, const moqctl_param* p) {
  return moqctl_loc_put(buf, at, p->loc);
}
static int moqctl_pp_bytes(wired_mspan buf, usz* at, const moqctl_param* p) {
  if (!moqvi_put(buf, at, p->bytes.n)) return 0;
  return bytes_put(buf, at, p->bytes);
}

/* Largest Location Filter: Type + Location + End Group Delta, three
 * 9-byte varints at most plus one. */
#define MOQCTL_LOCFILTER_MAX 28

static int moqctl_pp_locfilter(
    wired_mspan buf, usz* at, const moqctl_param* p) {
  u8  tmp[MOQCTL_LOCFILTER_MAX];
  usz n = 0;
  if (!moqctl_locfilter_put(wired_mspan_of(tmp, sizeof tmp), &n, &p->lf))
    return 0;
  if (!moqvi_put(buf, at, n)) return 0;
  return bytes_put(buf, at, wired_span_of(tmp, n));
}

static int moqctl_pp_raw(wired_mspan buf, usz* at, const moqctl_param* p) {
  return bytes_put(buf, at, p->bytes);
}

static int moqctl_pp_rangeloc22(
    wired_mspan buf, usz* at, const moqctl_param* p) {
  return moqctl_rangeloc22_put(buf, at, p->has_filter, &p->rl);
}

/* PENC_TOKEN re-emits the raw Token bytes the sender placed in p->bytes
 * (this subset only receives tokens; no Token-structure encoder). */
static const moqctl_param_put_fn MOQCTL_PARAM_PUT_FNS[8] = {
    moqctl_pp_uint8, moqctl_pp_varint,    moqctl_pp_location,
    moqctl_pp_bytes, moqctl_pp_bytes,     moqctl_pp_locfilter,
    moqctl_pp_raw,   moqctl_pp_rangeloc22};

static int moqctl_param_put_value(
    wired_mspan buf, usz* at, const moqctl_param* p) {
  return MOQCTL_PARAM_PUT_FNS[p->enc](buf, at, p);
}

static int moqctl_param_put_one(
    wired_mspan buf, usz* at, u64 prev, const moqctl_param* p) {
  if (p->type < prev) return 0;
  if (!moqvi_put(buf, at, p->type - prev)) return 0;
  return moqctl_param_put_value(buf, at, p);
}

static int moqctl_params_put_loop(
    wired_mspan buf, usz* at, const moqctl_params* params) {
  u64 prev = 0;
  for (usz i = 0; i < params->n; i++) {
    if (!moqctl_param_put_one(buf, at, prev, &params->items[i])) return 0;
    prev = params->items[i].type;
  }
  return 1;
}

int moqctl_params_put(wired_mspan buf, usz* off, const moqctl_params* params) {
  usz at = *off;
  if (!moqvi_put(buf, &at, params->n)) return 0;
  if (!moqctl_params_put_loop(buf, &at, params)) return 0;
  *off = at;
  return 1;
}

const moqctl_param* moqctl_params_find(const moqctl_params* params, u64 type) {
  for (usz i = 0; i < params->n; i++)
    if (params->items[i].type == type) return &params->items[i];
  return 0;
}

/* ===== SETUP (SS10.4) via Setup Options KVP list ===== */

static void moqctl_setup_apply_path_authority(
    moqctl_setup* out, const moqkvp* kv) {
  if (kv->type == MOQCTL_OPT_PATH) {
    out->has_path = 1;
    out->path     = kv->raw;
  }
  if (kv->type == MOQCTL_OPT_AUTHORITY) {
    out->has_authority = 1;
    out->authority     = kv->raw;
  }
}

/* Any option type not one of the three tracked here (including
 * greased/reserved ones) is ignored per SS10.4. */
static void moqctl_setup_apply_kvp(moqctl_setup* out, const moqkvp* kv) {
  moqctl_setup_apply_path_authority(out, kv);
  if (kv->type == MOQCTL_OPT_MOQT_IMPLEMENTATION) {
    out->has_implementation = 1;
    out->implementation     = kv->raw;
  }
}

static int moqctl_setup_take_one(
    wired_span buf, usz* at, u64* prev, moqctl_setup* out) {
  moqkvp kv;
  int    r = moqkvp_take(buf, at, prev, &kv);
  if (r != MOQKVP_OK) return MOQCTL_VIOLATION;
  moqctl_setup_apply_kvp(out, &kv);
  return MOQCTL_OK;
}

static int moqctl_setup_take_loop(wired_span buf, usz* at, moqctl_setup* out) {
  u64 prev = 0;
  while (*at < buf.n) {
    int r = moqctl_setup_take_one(buf, at, &prev, out);
    if (r != MOQCTL_OK) return r;
  }
  return MOQCTL_OK;
}

int moqctl_setup_take(wired_span buf, usz* off, moqctl_setup* out) {
  usz at = *off;
  int r;
  *out = (moqctl_setup){0};
  r    = moqctl_setup_take_loop(buf, &at, out);
  if (r != MOQCTL_OK) return r;
  *off = at;
  return MOQCTL_OK;
}

static int moqctl_setup_put_opt(
    wired_mspan buf, usz* at, u64* prev, u64 type, int has, wired_span val) {
  moqkvp kv;
  if (!has) return 1;
  kv.type   = type;
  kv.is_raw = 1;
  kv.raw    = val;
  return moqkvp_put(buf, at, prev, &kv);
}

static int moqctl_setup_put_path_authority(
    wired_mspan buf, usz* at, u64* prev, const moqctl_setup* s) {
  if (!moqctl_setup_put_opt(
          buf, at, prev, MOQCTL_OPT_PATH, s->has_path, s->path))
    return 0;
  return moqctl_setup_put_opt(
      buf, at, prev, MOQCTL_OPT_AUTHORITY, s->has_authority, s->authority);
}

int moqctl_setup_encode(wired_mspan buf, usz* off, const moqctl_setup* s) {
  usz at   = *off;
  u64 prev = 0;
  if (!moqctl_setup_put_path_authority(buf, &at, &prev, s)) return 0;
  if (!moqctl_setup_put_opt(
          buf, &at, &prev, MOQCTL_OPT_MOQT_IMPLEMENTATION,
          s->has_implementation, s->implementation))
    return 0;
  *off = at;
  return 1;
}

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

static wired_span moqctl_residual(wired_span buf, usz at) {
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

static int moqctl_publish_take_alias_params(
    int ver, wired_span buf, usz* at, moqctl_publish* out) {
  int r;
  if (!moqvi_take(buf, at, &out->track_alias)) return MOQCTL_INSUFFICIENT;
  r = moqctl_params_take(ver, buf, at, MOQCTL_PCTX_PUBLISH, &out->params);
  if (r != MOQCTL_OK) return r;
  out->track_properties = moqctl_residual(buf, *at);
  return MOQCTL_OK;
}

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

static int moqctl_redirect_take(wired_span buf, usz* at, moqctl_redirect* r) {
  int rr = moqctl_redirect_take_uri(buf, at, r);
  if (rr != MOQCTL_OK) return rr;
  rr = moqctl_ns_take_at(buf, at, &r->track_namespace);
  if (rr != MOQCTL_OK) return rr;
  return moqctl_name_take(buf, at, &r->track_name);
}

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
  if (!moqvi_take(buf, at, &out->error_code)) return MOQCTL_INSUFFICIENT;
  if (!moqvi_take(buf, at, &out->retry_interval)) return MOQCTL_INSUFFICIENT;
  return MOQCTL_OK;
}

static int moqctl_request_error_take_reason_redirect(
    wired_span buf, usz* at, moqctl_request_error* out) {
  int r = moqctl_reason_take(buf, at, &out->reason);
  if (r != MOQCTL_OK) return r;
  return moqctl_request_error_take_redirect(buf, at, out);
}

int moqctl_request_error_take(
    wired_span buf, usz* off, moqctl_request_error* out) {
  usz at = *off;
  int r  = moqctl_request_error_take_codes(buf, &at, out);
  if (r != MOQCTL_OK) return r;
  r = moqctl_request_error_take_reason_redirect(buf, &at, out);
  if (r != MOQCTL_OK) return r;
  *off = at;
  return MOQCTL_OK;
}

static int moqctl_redirect_put_uri(
    wired_mspan buf, usz* at, const moqctl_redirect* r) {
  if (!moqvi_put(buf, at, r->connect_uri.n)) return 0;
  return bytes_put(buf, at, r->connect_uri);
}

static int moqctl_redirect_put_name(
    wired_mspan buf, usz* at, const moqctl_redirect* r) {
  if (!moqvi_put(buf, at, r->track_name.n)) return 0;
  return bytes_put(buf, at, r->track_name);
}

static int moqctl_redirect_put(
    wired_mspan buf, usz* at, const moqctl_redirect* r) {
  if (!moqctl_redirect_put_uri(buf, at, r)) return 0;
  if (!moqctl_ns_put(buf, at, &r->track_namespace)) return 0;
  return moqctl_redirect_put_name(buf, at, r);
}

static int moqctl_request_error_encode_codes_reason(
    wired_mspan buf, usz* at, const moqctl_request_error* m) {
  if (!moqvi_put(buf, at, m->error_code)) return 0;
  if (!moqvi_put(buf, at, m->retry_interval)) return 0;
  return moqctl_reason_put(buf, at, m->reason);
}

static int moqctl_request_error_encode_redirect(
    wired_mspan buf, usz* at, const moqctl_request_error* m) {
  if (!m->has_redirect) return 1;
  return moqctl_redirect_put(buf, at, &m->redirect);
}

int moqctl_request_error_encode(
    wired_mspan buf, usz* off, const moqctl_request_error* m) {
  usz at = *off;
  if (!moqctl_request_error_encode_codes_reason(buf, &at, m)) return 0;
  if (!moqctl_request_error_encode_redirect(buf, &at, m)) return 0;
  *off = at;
  return 1;
}

/* ===== PUBLISH_DONE (SS10.10) ===== */

static int moqctl_publish_done_take_codes(
    wired_span buf, usz* at, moqctl_publish_done* out) {
  if (!moqvi_take(buf, at, &out->status_code)) return MOQCTL_INSUFFICIENT;
  if (!moqvi_take(buf, at, &out->stream_count)) return MOQCTL_INSUFFICIENT;
  return MOQCTL_OK;
}

int moqctl_publish_done_take(
    wired_span buf, usz* off, moqctl_publish_done* out) {
  usz at = *off;
  int r  = moqctl_publish_done_take_codes(buf, &at, out);
  if (r != MOQCTL_OK) return r;
  r = moqctl_reason_take(buf, &at, &out->reason);
  if (r != MOQCTL_OK) return r;
  *off = at;
  return MOQCTL_OK;
}

static int moqctl_publish_done_encode_codes(
    wired_mspan buf, usz* at, const moqctl_publish_done* m) {
  if (!moqvi_put(buf, at, m->status_code)) return 0;
  return moqvi_put(buf, at, m->stream_count);
}

int moqctl_publish_done_encode(
    wired_mspan buf, usz* off, const moqctl_publish_done* m) {
  usz at = *off;
  if (!moqctl_publish_done_encode_codes(buf, &at, m)) return 0;
  if (!moqctl_reason_put(buf, &at, m->reason)) return 0;
  *off = at;
  return 1;
}

/* ===== GOAWAY (SS10.3) ===== */

static int moqctl_goaway_take_uri(wired_span buf, usz* at, moqctl_goaway* out) {
  u64 uri_len;
  if (!moqctl_span_take_len(buf, at, &uri_len)) return MOQCTL_INSUFFICIENT;
  if (uri_len > MOQCTL_MAX_URI_LEN) return MOQCTL_VIOLATION;
  return moqctl_bytes_take(buf, at, uri_len, &out->new_session_uri);
}

int moqctl_goaway_take(wired_span buf, usz* off, moqctl_goaway* out) {
  usz at = *off;
  int r  = moqctl_goaway_take_uri(buf, &at, out);
  if (r != MOQCTL_OK) return r;
  if (!moqvi_take(buf, &at, &out->timeout)) return MOQCTL_INSUFFICIENT;
  *off = at;
  return MOQCTL_OK;
}

static int moqctl_goaway_encode_uri(
    wired_mspan buf, usz* at, const moqctl_goaway* m) {
  if (!moqvi_put(buf, at, m->new_session_uri.n)) return 0;
  return bytes_put(buf, at, m->new_session_uri);
}

int moqctl_goaway_encode(wired_mspan buf, usz* off, const moqctl_goaway* m) {
  usz at = *off;
  if (!moqctl_goaway_encode_uri(buf, &at, m)) return 0;
  if (!moqvi_put(buf, &at, m->timeout)) return 0;
  *off = at;
  return 1;
}

int moqctl_goaway18_take(wired_span buf, usz* off, moqctl_goaway* out) {
  usz at = *off;
  int r  = moqctl_goaway_take(buf, &at, out);
  if (r != MOQCTL_OK) return r;
  if (!moqvi_take(buf, &at, &out->request_id)) return MOQCTL_INSUFFICIENT;
  *off = at;
  return MOQCTL_OK;
}

int moqctl_goaway18_encode(wired_mspan buf, usz* off, const moqctl_goaway* m) {
  if (!moqctl_goaway_encode(buf, off, m)) return 0;
  return moqvi_put(buf, off, m->request_id);
}

/* ===== Common envelope (SS10) ===== */

/* Known-but-not-implemented Message Type IDs (SS10 table). Table-driven
 * so type classification stays a lookup, not an if/else chain. */
static const u64 MOQCTL_KNOWN_UNIMPL[] = {
    MOQTSTAT_T_REQUEST_UPDATE,   MOQFETCH_T_FETCH,
    MOQTSTAT_T_TRACK_STATUS,     MOQNS_T_PUBLISH_NAMESPACE,
    MOQNS_T_SUBSCRIBE_NAMESPACE, MOQCTL_T_SUBSCRIBE_TRACKS,
    MOQNS_T_NAMESPACE,           MOQNS_T_NAMESPACE_DONE,
    MOQCTL_T_PUBLISH_SKIPPED,    MOQFETCH_T_FETCH_OK,
};
#define MOQCTL_KNOWN_UNIMPL_N \
  (sizeof MOQCTL_KNOWN_UNIMPL / sizeof MOQCTL_KNOWN_UNIMPL[0])

static const u64 MOQCTL_KNOWN_IMPL[] = {
    MOQCTL_T_SETUP,        MOQCTL_T_GOAWAY,        MOQCTL_T_SUBSCRIBE,
    MOQCTL_T_SUBSCRIBE_OK, MOQCTL_T_REQUEST_ERROR, MOQCTL_T_REQUEST_OK,
    MOQCTL_T_PUBLISH_DONE, MOQCTL_T_PUBLISH,
};
#define MOQCTL_KNOWN_IMPL_N \
  (sizeof MOQCTL_KNOWN_IMPL / sizeof MOQCTL_KNOWN_IMPL[0])

static int moqctl_classify_type(u64 type) {
  if (moqctl_u64_in(MOQCTL_KNOWN_IMPL, MOQCTL_KNOWN_IMPL_N, type))
    return MOQCTL_OK;
  if (moqctl_u64_in(MOQCTL_KNOWN_UNIMPL, MOQCTL_KNOWN_UNIMPL_N, type))
    return MOQCTL_KNOWN_UNIMPLEMENTED;
  return MOQCTL_UNKNOWN_TYPE;
}

/* Types the draft-19 table above does not know: one row per wire Type,
 * defined in a draft whose caps include cap, with the Type it stands for
 * and its classification. Send side always uses the draft-19 Types
 * (REQUEST_OK is sent as 0x7). */
typedef struct {
  u32 cap;
  u64 wire;
  u64 type;
  int peek;
} moqctl_type_row;

static const moqctl_type_row MOQCTL_TYPE_ROWS[] = {
    /* draft-18 SS10 table vs SS10.5: 0x1E is PUBLISH_OK = REQUEST_OK. */
    {MOQVER_CAP_PUBLISH_OK_ALIAS, MOQCTL_T_PUBLISH_OK18, MOQCTL_T_REQUEST_OK,
     MOQCTL_OK},
    /* draft-22 SS9.10 PUBLISH_STATE_NOTIFY. */
    {MOQVER_CAP_PUBLISH_STATE_NOTIFY, MOQCTL_T_PUBLISH_STATE_NOTIFY,
     MOQCTL_T_PUBLISH_STATE_NOTIFY, MOQCTL_KNOWN_UNIMPLEMENTED},
};
#define MOQCTL_TYPE_ROWS_N \
  (sizeof MOQCTL_TYPE_ROWS / sizeof MOQCTL_TYPE_ROWS[0])

static int moqctl_type_row_is(const moqctl_type_row* r, int ver, u64 wire) {
  return r->wire == wire && (moqver_caps(ver) & r->cap);
}

static const moqctl_type_row* moqctl_type_row_for(int ver, u64 wire) {
  for (usz i = 0; i < MOQCTL_TYPE_ROWS_N; i++)
    if (moqctl_type_row_is(&MOQCTL_TYPE_ROWS[i], ver, wire))
      return &MOQCTL_TYPE_ROWS[i];
  return 0;
}

int moqctl_type_ver(int ver, int peek, u64* type) {
  const moqctl_type_row* r;
  if (peek != MOQCTL_UNKNOWN_TYPE) return peek;
  r = moqctl_type_row_for(ver, *type);
  if (!r) return peek;
  *type = r->type;
  return r->peek;
}

int moqctl_peek_header(wired_span buf, usz* at, u64* type, u16* len) {
  if (!moqvi_take(buf, at, type)) return MOQCTL_INSUFFICIENT;
  if (buf.n - *at < 2) return MOQCTL_INSUFFICIENT;
  *len = be_get_be16(buf.p + *at);
  *at += 2;
  return MOQCTL_OK;
}

/* A complete message of any Type is framed by its Length (SS10), so the
 * outputs are filled and *off skips it whatever the classification --
 * the caller decides what an unknown/unimplemented Type means. */
int moqctl_peek_type(
    wired_span buf, usz* off, u64* type_out, wired_span* body) {
  usz at = *off;
  u64 type;
  u16 len;
  int r = moqctl_peek_header(buf, &at, &type, &len);
  if (r != MOQCTL_OK) return r;
  if (buf.n - at < len) return MOQCTL_INSUFFICIENT;
  *type_out = type;
  *body     = wired_span_of(buf.p + at, len);
  *off      = at + len;
  return moqctl_classify_type(type);
}

/* A Message Body is framed by its Length (SS10), so running out of bytes
 * inside it, or bytes left over after it, is a Length mismatch: VIOLATION
 * (SS10 "If the length does not match ... PROTOCOL_VIOLATION"). */
static int moqctl_body_left(usz off, wired_span body) {
  return off == body.n ? MOQCTL_OK : MOQCTL_VIOLATION;
}

int moqctl_body_end(int r, usz off, wired_span body) {
  if (r == MOQCTL_INSUFFICIENT) return MOQCTL_VIOLATION;
  if (r != MOQCTL_OK) return r;
  return moqctl_body_left(off, body);
}
