#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_upf_holdable(
    const wired_moqt_hub* hub, const wired_moqtrun_fetch* f, usz n, usz cap);
static int moqtrun_upf_hold(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span rest, usz cap);
static int moqtrun_upf_blocked(const wired_moqtrun_fetch* f, wired_span rest);
static int moqtrun_upf_short(const wired_moqtrun_fetch* f, wired_span rest);
static int moqtrun_upf_cut(
    const wired_moqtrun_fetch* f, wired_span rest, int fin);
static int moqtrun_upf_keep(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span rest);
static int moqtrun_upf_tail_ok(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span rest, int fin);
static void moqtrun_upf_tail(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span rest, int fin);

/* What data holds of the payload still to pass through, written out;
 * the bytes of data that took (none when refused). */
usz moqtrun_upf_pass(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span data) {
  usz n = (usz)u64_min(f->up_pl_left, data.n);
  return n && moqtrun_upf_chunk(hub, f, wired_span_of(data.p, n)) ? n : 0;
}

/* ----- the upstream data stream ----- */

/* f's held tail followed by data, in hub->upf_buf (data alone when f
 * holds none); 0 when they do not fit. */
int moqtrun_upf_join(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f, wired_span* data) {
  if (hub->upf_owner != f) {
    return 1;
  }
  if (hub->upf_len + data->n > sizeof hub->upf_buf) {
    return 0;
  }
  bytes_memcpy(hub->upf_buf + hub->upf_len, data->p, data->n);
  *data = wired_span_of(hub->upf_buf, hub->upf_len + data->n);
  return 1;
}

static int moqtrun_upf_holdable(
    const wired_moqt_hub* hub, const wired_moqtrun_fetch* f, usz n, usz cap) {
  return (!hub->upf_owner || hub->upf_owner == f) && n < cap;
}

/* rest (under cap bytes) kept for f's next delivery; 0 when it cannot
 * be. */
static int moqtrun_upf_hold(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span rest, usz cap) {
  if (!rest.n) {
    moqtrun_upf_unhold(hub, f);
    return 1;
  }
  if (!moqtrun_upf_holdable(hub, f, rest.n, cap)) {
    return 0;
  }
  bytes_move_down(hub->upf_buf, rest.p, rest.n);
  hub->upf_len   = rest.n;
  hub->upf_owner = f;
  return 1;
}

/* The transport refused the payload under way: rest starts with it. */
static int moqtrun_upf_blocked(const wired_moqtrun_fetch* f, wired_span rest) {
  return rest.n && f->up_pl_left;
}

/* Some Object is not all in: its head (rest) or its payload. */
static int moqtrun_upf_short(const wired_moqtrun_fetch* f, wired_span rest) {
  return rest.n || f->up_pl_left;
}

/* A FIN cutting an Object short -- not a refused payload, which only
 * waits. */
static int moqtrun_upf_cut(
    const wired_moqtrun_fetch* f, wired_span rest, int fin) {
  return fin && moqtrun_upf_short(f, rest) && !moqtrun_upf_blocked(f, rest);
}

/* rest kept: what a refusal left (all of it, to retry), else a torn
 * small Object or head. */
static int moqtrun_upf_keep(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span rest) {
  if (moqtrun_upf_blocked(f, rest)) {
    return moqtrun_upf_hold(hub, f, rest, sizeof hub->upf_buf + 1);
  }
  return moqtrun_upf_hold(hub, f, rest, WIRED_MOQTRUN_RELAY_FRAG_MAX);
}

/* A FIN cut no Object short, and rest could be kept. */
static int moqtrun_upf_tail_ok(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span rest, int fin) {
  return !moqtrun_upf_cut(f, rest, fin) && moqtrun_upf_keep(hub, f, rest);
}

static void moqtrun_upf_tail(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span rest, int fin) {
  if (!moqtrun_upf_tail_ok(hub, f, rest, fin)) {
    moqtrun_upf_fail(hub, f, MOQTRUN_UPF_IO_CANCEL, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  f->up_data_end = fin;
  moqtrun_upf_done_if(hub, f);
}

/* After the whole items: a malformed one closes the upstream session
 * (11.4.4: e.g. a Group or Object ID out of range), a torn one is kept. */
void moqtrun_upf_rest(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    int                  r,
    wired_span           rest,
    int                  fin) {
  if (!moqtrun_upf_live(f)) {
    return;
  }
  if (r < MOQCTL_INSUFFICIENT) {
    moqtrun_close_with(hub, pp, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
    moqtrun_upf_fail(hub, f, MOQTRUN_UPF_IO_NONE, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  moqtrun_upf_tail(hub, f, rest, fin);
}
