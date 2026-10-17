#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_setup_put_opt(
    wired_mspan buf, usz* at, u64* prev, u64 type, int has, wired_span val);
static int moqctl_setup_put_path_authority(
    wired_mspan buf, usz* at, u64* prev, const moqctl_setup* s);
static int moqctl_setup_put_num(
    wired_mspan buf, usz* at, u64* prev, u64 type, u64 v);
static int moqctl_setup_put_tail(
    wired_mspan buf, usz* at, u64* prev, const moqctl_setup* s);
static usz moqctl_ssts_count(const moqctl_setup* s);
static int moqctl_ssts_put_list(wired_mspan b, usz* at, const moqctl_setup* s);
static int moqctl_setup_put_ssts(
    wired_mspan buf, usz* at, u64* prev, const moqctl_setup* s);
static int moqctl_setup_put_rest(
    wired_mspan buf, usz* at, u64* prev, const moqctl_setup* s);

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

/* An even (varint-valued) option; 0, the draft default, stays off the
 * wire. */
static int moqctl_setup_put_num(
    wired_mspan buf, usz* at, u64* prev, u64 type, u64 v) {
  moqkvp kv;
  if (!v) return 1;
  kv.type   = type;
  kv.is_raw = 0;
  kv.num    = v;
  return moqkvp_put(buf, at, prev, &kv);
}

/* Ascending option order per moqkvp_put's Delta contract: 0x06, 0x07,
 * 0x08. */
static int moqctl_setup_put_tail(
    wired_mspan buf, usz* at, u64* prev, const moqctl_setup* s) {
  if (!moqctl_setup_put_num(
          buf, at, prev, MOQCTL_OPT_MAX_FILTER_RANGES, s->max_filter_ranges))
    return 0;
  if (!moqctl_setup_put_opt(
          buf, at, prev, MOQCTL_OPT_MOQT_IMPLEMENTATION, s->has_implementation,
          s->implementation))
    return 0;
  return moqctl_setup_put_num(
      buf, at, prev, MOQCTL_OPT_MAX_REQUEST_UPDATES, s->max_request_updates);
}

static usz moqctl_ssts_count(const moqctl_setup* s) {
  return (usz)u64_min(s->ssts_alg_n, MOQCTL_SSTS_MAX_ALGS);
}

static int moqctl_ssts_put_list(wired_mspan b, usz* at, const moqctl_setup* s) {
  usz n = moqctl_ssts_count(s);
  for (usz i = 0; i < n; i++)
    if (!moqvi_put(b, at, s->ssts_algs[i])) return 0;
  return 1;
}

/* SSTS_ALGORITHMS (0x09) follows MAX_REQUEST_UPDATES (0x08). */
static int moqctl_setup_put_ssts(
    wired_mspan buf, usz* at, u64* prev, const moqctl_setup* s) {
  u8  tmp[MOQCTL_SSTS_MAX_ALGS * 9]; /* moqvi: 9 bytes at most */
  usz n = 0;
  if (!s->has_ssts) return 1;
  if (!moqctl_ssts_put_list(wired_mspan_of(tmp, sizeof tmp), &n, s)) return 0;
  return moqctl_setup_put_opt(
      buf, at, prev, MOQCTL_OPT_SSTS_ALGORITHMS, 1, wired_span_of(tmp, n));
}

static int moqctl_setup_put_rest(
    wired_mspan buf, usz* at, u64* prev, const moqctl_setup* s) {
  if (!moqctl_setup_put_tail(buf, at, prev, s)) return 0;
  return moqctl_setup_put_ssts(buf, at, prev, s);
}

int moqctl_setup_encode(wired_mspan buf, usz* off, const moqctl_setup* s) {
  usz at   = *off;
  u64 prev = 0;
  if (!moqctl_setup_put_path_authority(buf, &at, &prev, s)) return 0;
  if (!moqctl_setup_put_rest(buf, &at, &prev, s)) return 0;
  *off = at;
  return 1;
}
