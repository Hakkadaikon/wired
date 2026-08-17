#include "app/moqt/ctl/moqctl.h"

#include "app/moqt/kvp/moqkvp.h"
#include "app/moqt/vi/moqvi.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

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
    MOQCTL_ERR_REDIRECT};
#define MOQCTL_KNOWN_ERRS_N (sizeof MOQCTL_KNOWN_ERRS / sizeof(u64))

u64 moqctl_known_request_error(u64 code) {
  if (moqctl_u64_in(MOQCTL_KNOWN_ERRS, MOQCTL_KNOWN_ERRS_N, code)) return code;
  return MOQCTL_ERR_INTERNAL_ERROR;
}

static const u64 MOQCTL_KNOWN_DONE[] = {
    MOQCTL_DONE_INTERNAL_ERROR, MOQCTL_DONE_TRACK_ENDED,
    MOQCTL_DONE_GOING_AWAY};
#define MOQCTL_KNOWN_DONE_N (sizeof MOQCTL_KNOWN_DONE / sizeof(u64))

u64 moqctl_known_publish_done(u64 code) {
  if (moqctl_u64_in(MOQCTL_KNOWN_DONE, MOQCTL_KNOWN_DONE_N, code)) return code;
  return MOQCTL_DONE_INTERNAL_ERROR;
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
  if (out->end_group_delta > (u64)-1 - out->start.group)
    return MOQCTL_VIOLATION;
  return MOQCTL_OK;
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

static int moqctl_ns_take_at(wired_span buf, usz* at, moqctl_ns* ns) {
  int r = moqctl_ns_take_count(buf, at, ns);
  if (r != MOQCTL_OK) return r;
  return moqctl_ns_take_fields(buf, at, ns);
}

int moqctl_ns_take(wired_span buf, usz* off, moqctl_ns* out) {
  usz at = *off;
  int r  = moqctl_ns_take_at(buf, &at, out);
  if (r != MOQCTL_OK) return r;
  *off = at;
  return MOQCTL_OK;
}

static usz moqctl_ns_bytelen(const moqctl_ns* ns) {
  usz total = 0;
  for (usz i = 0; i < ns->n; i++) total += ns->fields[i].n;
  return total;
}

static int moqctl_name_take(wired_span buf, usz* at, wired_span* name) {
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

static int moqctl_ns_put(wired_mspan buf, usz* at, const moqctl_ns* ns) {
  if (!moqvi_put(buf, at, ns->n)) return 0;
  return moqctl_ns_put_fields(buf, at, ns);
}

static int moqctl_name_put(wired_mspan buf, usz* at, wired_span name) {
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

/* Legality table: which known parameter types are allowed in which
 * message, and what encoding each uses. Table-driven to keep dispatch a
 * single lookup instead of an if/else chain per type. */
typedef struct {
  u64 type;
  int enc;
  u64 allowed_msgs[4]; /* remaining slots are 0 (no real type is 0) */
} moqctl_param_rule;

static const moqctl_param_rule MOQCTL_PARAM_RULES[] = {
    {MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT,
     MOQCTL_PENC_VARINT,
     {MOQCTL_T_SUBSCRIBE, 0, 0, 0}},
    {MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT,
     MOQCTL_PENC_VARINT,
     {MOQCTL_T_SUBSCRIBE, 0, 0, 0}},
    {MOQCTL_PARAM_FORWARD,
     MOQCTL_PENC_UINT8,
     {MOQCTL_T_SUBSCRIBE, MOQCTL_T_PUBLISH, 0, 0}},
};
#define MOQCTL_PARAM_RULE_N \
  (sizeof MOQCTL_PARAM_RULES / sizeof MOQCTL_PARAM_RULES[0])

static const moqctl_param_rule* moqctl_param_rule_for(u64 type) {
  for (usz i = 0; i < MOQCTL_PARAM_RULE_N; i++)
    if (MOQCTL_PARAM_RULES[i].type == type) return &MOQCTL_PARAM_RULES[i];
  return 0;
}

static int moqctl_param_allowed_in(const moqctl_param_rule* rule, u64 msg) {
  return moqctl_u64_in(rule->allowed_msgs, 4, msg);
}

static int moqctl_param_take_uint8(wired_span buf, usz* at, u64* out) {
  if (buf.n - *at < 1) return MOQCTL_INSUFFICIENT;
  *out = buf.p[*at];
  *at += 1;
  return MOQCTL_OK;
}

static int moqctl_param_take_varint(wired_span buf, usz* at, u64* out) {
  return moqvi_take(buf, at, out) ? MOQCTL_OK : MOQCTL_INSUFFICIENT;
}

/* Value dispatch table: one function per encoding, indexed by
 * QUIC_MOQCTL_PENC_*, so the caller never branches on enc itself. */
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

static const moqctl_param_value_fn MOQCTL_PARAM_VALUE_FNS[4] = {
    moqctl_pv_uint8, moqctl_pv_varint, moqctl_pv_location, moqctl_pv_bytes};

static int moqctl_param_take_value(
    wired_span buf, usz* at, int enc, moqctl_param* p) {
  return MOQCTL_PARAM_VALUE_FNS[enc](buf, at, p);
}

/* Known type: enforce scope + encoding via the rule table. Unknown Type:
 * always a VIOLATION per SS10.2 (no skip mechanism exists). */
static int moqctl_param_take_known(
    wired_span buf, usz* at, u64 msg_type, moqctl_param* p) {
  const moqctl_param_rule* rule = moqctl_param_rule_for(p->type);
  if (!rule) return MOQCTL_VIOLATION;
  if (!moqctl_param_allowed_in(rule, msg_type)) return MOQCTL_VIOLATION;
  p->enc = rule->enc;
  return moqctl_param_take_value(buf, at, rule->enc, p);
}

static int moqctl_param_dup(const moqctl_params* out, u64 type) {
  for (usz i = 0; i < out->n; i++)
    if (out->items[i].type == type) return 1;
  return 0;
}

static int moqctl_param_take_delta(
    wired_span buf, usz* at, u64 prev, moqctl_param* p) {
  u64 delta;
  if (!moqvi_take(buf, at, &delta)) return MOQCTL_INSUFFICIENT;
  if (delta > (u64)-1 - prev) return MOQCTL_VIOLATION;
  p->type = prev + delta;
  return MOQCTL_OK;
}

static int moqctl_param_take_body(
    wired_span     buf,
    usz*           at,
    u64            msg_type,
    moqctl_params* out,
    moqctl_param*  p) {
  if (moqctl_param_dup(out, p->type)) return MOQCTL_VIOLATION;
  return moqctl_param_take_known(buf, at, msg_type, p);
}

static int moqctl_param_take_one(
    wired_span buf, usz* at, u64 msg_type, u64 prev, moqctl_params* out) {
  moqctl_param p = {0};
  int          r = moqctl_param_take_delta(buf, at, prev, &p);
  if (r != MOQCTL_OK) return r;
  r = moqctl_param_take_body(buf, at, msg_type, out, &p);
  if (r != MOQCTL_OK) return r;
  out->items[out->n] = p;
  out->n++;
  return MOQCTL_OK;
}

static int moqctl_params_take_step(
    wired_span buf, usz* at, u64 msg_type, u64* prev, moqctl_params* out) {
  int r;
  if (out->n >= MOQCTL_MAX_PARAMS) return MOQCTL_VIOLATION;
  r = moqctl_param_take_one(buf, at, msg_type, *prev, out);
  if (r != MOQCTL_OK) return r;
  *prev = out->items[out->n - 1].type;
  return MOQCTL_OK;
}

static int moqctl_params_take_loop(
    wired_span buf, usz* at, u64 msg_type, u64 count, moqctl_params* out) {
  u64 prev = 0;
  for (u64 i = 0; i < count; i++) {
    int r = moqctl_params_take_step(buf, at, msg_type, &prev, out);
    if (r != MOQCTL_OK) return r;
  }
  return MOQCTL_OK;
}

int moqctl_params_take(
    wired_span buf, usz* off, u64 msg_type, moqctl_params* out) {
  usz at = *off;
  u64 count;
  int r;
  out->n = 0;
  if (!moqvi_take(buf, &at, &count)) return MOQCTL_INSUFFICIENT;
  r = moqctl_params_take_loop(buf, &at, msg_type, count, out);
  if (r != MOQCTL_OK) return r;
  *off = at;
  return MOQCTL_OK;
}

static int moqctl_param_put_uint8(wired_mspan buf, usz* at, u64 v) {
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

static const moqctl_param_put_fn MOQCTL_PARAM_PUT_FNS[4] = {
    moqctl_pp_uint8, moqctl_pp_varint, moqctl_pp_location, moqctl_pp_bytes};

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
    wired_span buf, usz* at, moqctl_subscribe* out) {
  int r = moqctl_ftn_take(buf, at, &out->name);
  if (r != MOQCTL_OK) return r;
  return moqctl_params_take(buf, at, MOQCTL_T_SUBSCRIBE, &out->params);
}

int moqctl_subscribe_take(wired_span buf, usz* off, moqctl_subscribe* out) {
  usz at = *off;
  int r;
  if (!moqvi_take(buf, &at, &out->request_id)) return MOQCTL_INSUFFICIENT;
  r = moqctl_subscribe_take_body(buf, &at, out);
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
    wired_span buf, usz* off, moqctl_subscribe_ok* out) {
  usz at = *off;
  int r;
  if (!moqvi_take(buf, &at, &out->track_alias)) return MOQCTL_INSUFFICIENT;
  r = moqctl_params_take(buf, &at, MOQCTL_T_SUBSCRIBE_OK, &out->params);
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
    wired_span buf, usz* at, moqctl_publish* out) {
  int r;
  if (!moqvi_take(buf, at, &out->track_alias)) return MOQCTL_INSUFFICIENT;
  r = moqctl_params_take(buf, at, MOQCTL_T_PUBLISH, &out->params);
  if (r != MOQCTL_OK) return r;
  out->track_properties = moqctl_residual(buf, *at);
  return MOQCTL_OK;
}

static int moqctl_publish_take_id_name(
    wired_span buf, usz* at, moqctl_publish* out) {
  if (!moqvi_take(buf, at, &out->request_id)) return MOQCTL_INSUFFICIENT;
  return moqctl_ftn_take(buf, at, &out->name);
}

int moqctl_publish_take(wired_span buf, usz* off, moqctl_publish* out) {
  usz at = *off;
  int r  = moqctl_publish_take_id_name(buf, &at, out);
  if (r != MOQCTL_OK) return r;
  r = moqctl_publish_take_alias_params(buf, &at, out);
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
 * this codec does not track (session-layer concern). Decoding with
 * MOQCTL_T_REQUEST_OK (which has no rule-table entries) means any
 * parameter type is unknown/VIOLATION -- matching golden vectors, which
 * all carry zero parameters. */
int moqctl_request_ok_take(wired_span buf, usz* off, moqctl_request_ok* out) {
  usz at = *off;
  int r  = moqctl_params_take(buf, &at, MOQCTL_T_REQUEST_OK, &out->params);
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

/* ===== Common envelope (SS10) ===== */

/* Known-but-not-implemented Message Type IDs (SS10 table). Table-driven
 * so type classification stays a lookup, not an if/else chain. */
static const u64 MOQCTL_KNOWN_UNIMPL[] = {
    0x2,  /* REQUEST_UPDATE */
    0x16, /* FETCH */
    0xD,  /* TRACK_STATUS */
    0x6,  /* PUBLISH_NAMESPACE */
    0x50, /* SUBSCRIBE_NAMESPACE */
    0x51, /* SUBSCRIBE_TRACKS */
    0x8,  /* NAMESPACE */
    0xE,  /* NAMESPACE_DONE */
    0xF,  /* PUBLISH_SKIPPED */
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

static int moqctl_peek_header(wired_span buf, usz* at, u64* type, u16* len) {
  if (!moqvi_take(buf, at, type)) return MOQCTL_INSUFFICIENT;
  if (buf.n - *at < 2) return MOQCTL_INSUFFICIENT;
  *len = be_get_be16(buf.p + *at);
  *at += 2;
  return MOQCTL_OK;
}

/* Header already read: check the body fits and the Type is one this codec
 * accepts (known-implemented). */
static int moqctl_peek_body(wired_span buf, usz at, u64 type, u16 len) {
  if (buf.n - at < len) return MOQCTL_INSUFFICIENT;
  return moqctl_classify_type(type);
}

int moqctl_peek_type(
    wired_span buf, usz* off, u64* type_out, wired_span* body) {
  usz at = *off;
  u64 type;
  u16 len;
  int r = moqctl_peek_header(buf, &at, &type, &len);
  if (r != MOQCTL_OK) return r;
  r = moqctl_peek_body(buf, at, type, len);
  if (r != MOQCTL_OK) return r;
  *type_out = type;
  *body     = wired_span_of(buf.p + at, len);
  *off      = at + len;
  return MOQCTL_OK;
}
