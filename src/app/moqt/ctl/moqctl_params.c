#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_param_put_value(
    wired_mspan buf, usz* at, const moqctl_param* p);
static int moqctl_param_put_one(
    wired_mspan buf, usz* at, u64 prev, const moqctl_param* p);
static int moqctl_params_put_loop(
    wired_mspan buf, usz* at, const moqctl_params* params);

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
