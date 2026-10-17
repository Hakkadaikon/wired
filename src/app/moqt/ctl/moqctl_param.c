#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_reason_take_len(wired_span buf, usz* at, u64* len);
static int moqctl_param_take_varint(wired_span buf, usz* at, u64* out);

/* ===== Reason Phrase (SS1.4.4) ===== */

static int moqctl_reason_take_len(wired_span buf, usz* at, u64* len) {
  if (!moqctl_span_take_len(buf, at, len)) {
    return MOQCTL_INSUFFICIENT;
  }
  if (*len > MOQCTL_MAX_REASON_LEN) {
    return MOQCTL_VIOLATION;
  }
  return MOQCTL_OK;
}

int moqctl_reason_take(wired_span buf, usz* off, moqctl_reason* out) {
  usz at = *off;
  u64 len;
  int r = moqctl_reason_take_len(buf, &at, &len);
  if (r != MOQCTL_OK) {
    return r;
  }
  r = moqctl_bytes_take(buf, &at, len, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  *off = at;
  return MOQCTL_OK;
}

int moqctl_reason_put(wired_mspan buf, usz* off, moqctl_reason reason) {
  usz at = *off;
  if (!moqvi_put(buf, &at, reason.n)) {
    return 0;
  }
  if (!bytes_put(buf, &at, reason)) {
    return 0;
  }
  *off = at;
  return 1;
}

/* ctx sets, {draft-22, draft-19, draft-18}: each draft's "MAY appear in"
 * (22 SS9.20.x, 19 SS10.2.x, 18 SS10.2.x). draft-19 adds SUBSCRIBE_TRACKS
 * for every SUBSCRIBE parameter (19 SS10.19.1); draft-19 PUBLISH also takes
 * GROUP_ORDER, which a SUBSCRIBE_TRACKS-generated PUBLISH echoes (19
 * SS10.19.1 "will include the GROUP_ORDER parameter"). An
 * unqualified "REQUEST_UPDATE" covers every REQUEST_UPDATE kind.
 * RENDEZVOUS and FILL timeouts state no encoding; varint is assumed. Range
 * filters (5.1.3) and FILL_PARAMETERS (22 SS9.20.15: Number of Parameters
 * + Parameters) are kept as their raw Length-prefixed bytes. SWITCH_FROM
 * and SWITCHING_SET_ASSIGNMENT are moqtail's experimental track-switching
 * extensions: draft-22 SUBSCRIBE + REQUEST_UPDATE (subscription) only. */
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
    {MOQCTL_PARAM_GROUP_ORDER,               MOQCTL_PENC_UINT8,     {0x1015,  0x1015,  0x19},    1, 2,   0},
    {MOQCTL_PARAM_FILL_PARAMETERS,           MOQCTL_PENC_BYTES,     {0x4001,  0,       0},       0, 0,   0},
    {MOQCTL_PARAM_SUBGROUP_FILTER,           MOQCTL_PENC_BYTES,     {0x5011,  0x5019,  0},       0, 0,   1},
    {MOQCTL_PARAM_OBJECTID_FILTER,           MOQCTL_PENC_BYTES,     {0x5011,  0x5019,  0},       0, 0,   1},
    {MOQCTL_PARAM_PRIORITY_FILTER,           MOQCTL_PENC_BYTES,     {0x5011,  0x5019,  0},       0, 0,   1},
    {MOQCTL_PARAM_OBJECT_PROPERTY_FILTER,    MOQCTL_PENC_BYTES,     {0x5011,  0x5019,  0},       0, 0,   1},
    {MOQCTL_PARAM_TRACK_PROPERTY_FILTER,     MOQCTL_PENC_BYTES,     {0x21000, 0x21000, 0},       0, 0,   1},
    {MOQCTL_PARAM_NEW_GROUP_REQUEST,         MOQCTL_PENC_VARINT,    {0x4001,  0x5009,  0x4009},  0, 0,   0},
    {MOQCTL_PARAM_TRACK_NAMESPACE_PREFIX,    MOQCTL_PENC_NS,        {0x30000, 0x30000, 0x30000}, 0, 0,   0},
    {MOQCTL_PARAM_INCLUDE_PROPERTIES,        MOQCTL_PENC_UINT8,     {0x1051,  0,       0},       0, 1,   0},
    {MOQCTL_PARAM_SWITCH_FROM,               MOQCTL_PENC_SWITCHFROM, {0x4001, 0,       0},       0, 0,   0},
    {MOQCTL_PARAM_SWITCHING_SET_ASSIGNMENT,  MOQCTL_PENC_SSA,       {0x4001,  0,       0},       0, 0,   0},
};

const moqctl_param_rule* moqctl_param_rule_for(u64 type) {
  for (usz i = 0; i < MOQCTL_PARAM_RULE_N; i++)
    if (MOQCTL_PARAM_RULES[i].type == type) return &MOQCTL_PARAM_RULES[i];
  return 0;
}

int moqctl_param_allowed_in(
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

int moqctl_pv_uint8(wired_span buf, usz* at, moqctl_param* p) {
  return moqctl_param_take_uint8(buf, at, &p->u8v);
}

int moqctl_pv_varint(wired_span buf, usz* at, moqctl_param* p) {
  return moqctl_param_take_varint(buf, at, &p->vi);
}

int moqctl_pv_location(wired_span buf, usz* at, moqctl_param* p) {
  return moqctl_loc_take(buf, at, &p->loc);
}
