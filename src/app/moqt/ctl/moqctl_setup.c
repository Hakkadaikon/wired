#include "app/moqt/ctl/moqctl_impl.h"

static void moqctl_setup_apply_path_authority(
    moqctl_setup* out, const moqkvp* kv);
static void moqctl_setup_apply_limits(moqctl_setup* out, const moqkvp* kv);
static int  moqctl_ssts_known(u64 alg);
static void moqctl_ssts_keep(moqctl_setup* out, u64 alg, int known);
static int  moqctl_ssts_take_list(wired_span v, moqctl_setup* out, int known);
static int  moqctl_setup_apply_ssts(moqctl_setup* out, const moqkvp* kv);
static int  moqctl_setup_apply_kvp(moqctl_setup* out, const moqkvp* kv);
static int  moqctl_setup_take_one(
    wired_span buf, usz* at, u64* prev, moqctl_setup* out);
static int moqctl_setup_take_loop(wired_span buf, usz* at, moqctl_setup* out);

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

/* MAX_FILTER_RANGES / MAX_REQUEST_UPDATES (SS10.4): even option types,
 * their value one varint (kv->num). */
static void moqctl_setup_apply_limits(moqctl_setup* out, const moqkvp* kv) {
  if (kv->type == MOQCTL_OPT_MAX_FILTER_RANGES) {
    out->max_filter_ranges = kv->num;
  }
  if (kv->type == MOQCTL_OPT_MAX_REQUEST_UPDATES) {
    out->max_request_updates = kv->num;
  }
}

/* SSTS_ALGORITHMS (moqtail): concatenated varints, no count. Two passes
 * over the list: the ids this SDK knows first, then the unknown ones while
 * room is left, so a peer listing many ids with 0xff01 last still
 * negotiates it. */
static int moqctl_ssts_known(u64 alg) {
  return alg == MOQCTL_SSTS_ALG_DEFAULT || alg == MOQCTL_SSTS_ALG_BACKPRESSURE;
}

static void moqctl_ssts_keep(moqctl_setup* out, u64 alg, int known) {
  if (moqctl_ssts_known(alg) != known) {
    return;
  }
  if (out->ssts_alg_n >= MOQCTL_SSTS_MAX_ALGS) {
    return;
  }
  out->ssts_algs[out->ssts_alg_n++] = alg;
}

/* 1 when v is a whole number of varints, 0 when it ends mid-varint. */
static int moqctl_ssts_take_list(wired_span v, moqctl_setup* out, int known) {
  usz at = 0;
  u64 alg;
  while (at < v.n) {
    if (!moqvi_take(v, &at, &alg)) {
      return 0;
    }
    moqctl_ssts_keep(out, alg, known);
  }
  return 1;
}

/* draft-22 SS1.4 (18/19 SS1.4.3): a Key-Value-Pair whose value cannot be
 * parsed closes the session KEY_VALUE_FORMATTING_ERROR, so a list ending
 * mid-varint is MOQCTL_PARAMS_KVFMT. A repeat replaces the earlier one. */
static int moqctl_setup_apply_ssts(moqctl_setup* out, const moqkvp* kv) {
  if (kv->type != MOQCTL_OPT_SSTS_ALGORITHMS) {
    return MOQCTL_OK;
  }
  out->ssts_alg_n = 0;
  if (!moqctl_ssts_take_list(kv->raw, out, 1)) {
    return MOQCTL_PARAMS_KVFMT;
  }
  moqctl_ssts_take_list(kv->raw, out, 0);
  out->has_ssts = 1;
  return MOQCTL_OK;
}

/* Any option type not one of the six tracked here (including
 * greased/reserved ones) is ignored per SS10.4. */
static int moqctl_setup_apply_kvp(moqctl_setup* out, const moqkvp* kv) {
  moqctl_setup_apply_path_authority(out, kv);
  moqctl_setup_apply_limits(out, kv);
  if (kv->type == MOQCTL_OPT_MOQT_IMPLEMENTATION) {
    out->has_implementation = 1;
    out->implementation     = kv->raw;
  }
  return moqctl_setup_apply_ssts(out, kv);
}

static int moqctl_setup_take_one(
    wired_span buf, usz* at, u64* prev, moqctl_setup* out) {
  moqkvp kv;
  int    r = moqkvp_take(buf, at, prev, &kv);
  if (r != MOQKVP_OK) {
    return MOQCTL_VIOLATION;
  }
  return moqctl_setup_apply_kvp(out, &kv);
}

static int moqctl_setup_take_loop(wired_span buf, usz* at, moqctl_setup* out) {
  u64 prev = 0;
  while (*at < buf.n) {
    int r = moqctl_setup_take_one(buf, at, &prev, out);
    if (r != MOQCTL_OK) {
      return r;
    }
  }
  return MOQCTL_OK;
}

int moqctl_setup_take(wired_span buf, usz* off, moqctl_setup* out) {
  usz at = *off;
  int r;
  *out = (moqctl_setup){0};
  r    = moqctl_setup_take_loop(buf, &at, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  *off = at;
  return MOQCTL_OK;
}
