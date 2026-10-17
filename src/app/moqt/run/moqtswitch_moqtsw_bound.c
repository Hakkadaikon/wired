#include "app/moqt/run/moqtswitch_impl.h"

static u64  moqtsw_next(const wired_moqtrun_track* t);
static int  moqtsw_ends_by(const wired_moqtrun_sub* s, u64 e);
static void moqtsw_end_at(wired_moqtrun_sub* s, u64 e);
static void moqtsw_bound_none(wired_moqtrun_sub* s);
static void moqtsw_bound_old(wired_moqtrun_sub* s);
static void moqtsw_bound_new(wired_moqtrun_sub* s);
static void moqtsw_new_side(
    const moqtsw_ops* ops, wired_moqtrun_track* t, wired_moqtrun_sub* s, u64 g);
static void moqtsw_old_side(
    const wired_moqt_hub*    hub,
    wired_moqtrun_sub*       a,
    const wired_moqtrun_sub* b,
    const moqctl_switchfrom* sw,
    u64                      g);
static void moqtsw_start(
    wired_moqt_hub*          hub,
    const moqtsw_ops*        ops,
    wired_moqtrun_track*     t,
    wired_moqtrun_sub*       s,
    const moqctl_switchfrom* sw);

/* ===================== bounds (TS-1, TS-2) ===================== */

/* The group after t's Largest, 0 when t has none. */
static u64 moqtsw_next(const wired_moqtrun_track* t) {
  return t->has_largest ? t->largest.group + 1 : 0;
}

/* s already ends at or before Group e. */
static int moqtsw_ends_by(const wired_moqtrun_sub* s, u64 e) {
  return s->has_end_group && s->end_group <= e;
}

/* End no later than Group e, whole (an End Object of a later Group no
 * longer applies). */
static void moqtsw_end_at(wired_moqtrun_sub* s, u64 e) {
  if (moqtsw_ends_by(s, e)) {
    return;
  }
  s->end_group      = e;
  s->has_end_group  = 1;
  s->has_end_object = 0;
}

static void moqtsw_bound_none(wired_moqtrun_sub* s) { (void)s; }

/* A: up to G-1; with G 0 nothing at all (moqtsw_step ends it at once). */
static void moqtsw_bound_old(wired_moqtrun_sub* s) {
  if (!s->sw_g) {
    s->forward_off = 1;
    return;
  }
  moqtsw_end_at(s, s->sw_g - 1);
}

/* B: from {G, 0}, never earlier than its own filter asked. */
static void moqtsw_bound_new(wired_moqtrun_sub* s) {
  moqctl_loc g = moqctl_loc_of(s->sw_g, 0);
  if (moqctl_loc_less(s->start, g)) {
    s->start = g;
  }
}

static void (*const MOQTSW_BOUND_FNS[])(wired_moqtrun_sub*) = {
    moqtsw_bound_none, moqtsw_bound_old, moqtsw_bound_new};

void moqtsw_rebound(wired_moqtrun_sub* s) { MOQTSW_BOUND_FNS[s->sw_role](s); }

void moqtsw_reattached(
    wired_moqt_hub* hub, const moqtsw_ops* ops, wired_moqtrun_sub* s) {
  moqtsw_orphan(hub, ops, s); /* A ended while B waited: no sweep saw B */
  moqtsw_rebound(s);
  hub->sw_live += (u32)(s->sw_role == MOQTSW_ROLE_OLD);
}

/* ===================== begin ===================== */

/* B is (re)activated: its filter re-resolved (a bound left by an earlier
 * switch away from it goes), FORWARD 1, start at G. */
static void moqtsw_new_side(
    const moqtsw_ops*    ops,
    wired_moqtrun_track* t,
    wired_moqtrun_sub*   s,
    u64                  g) {
  ops->resolve(s, t);
  moqtsw_sub_clear(s);
  s->sw_role     = MOQTSW_ROLE_NEW;
  s->sw_g        = g;
  s->forward_off = 0;
  moqtsw_rebound(s);
}

/* A remembers what ends it: B's Request ID (Hard fires once B's track
 * reached G, or B is gone). */
static void moqtsw_old_side(
    const wired_moqt_hub*    hub,
    wired_moqtrun_sub*       a,
    const wired_moqtrun_sub* b,
    const moqctl_switchfrom* sw,
    u64                      g) {
  a->sw_role     = MOQTSW_ROLE_OLD;
  a->sw_mode     = (u8)(sw->mode == MOQCTL_SWITCH_SOFT);
  a->sw_done     = (u8)(sw->publish_done != 0);
  a->sw_g        = g;
  a->sw_peer_rid = b->request_id;
  a->sw_deadline = hub->live.last_now_ms + WIRED_MOQTSW_SOFT_WAIT_MS;
  moqtsw_rebound(a);
}

static void moqtsw_start(
    wired_moqt_hub*          hub,
    const moqtsw_ops*        ops,
    wired_moqtrun_track*     t,
    wired_moqtrun_sub*       s,
    const moqctl_switchfrom* sw) {
  wired_moqtrun_track* ot = 0;
  wired_moqtrun_sub*   a  = ops->find(hub, s->session_idx, sw->request_id, &ot);
  if (!a) {
    return; /* checked in this same dispatch: cannot happen */
  }
  u64 g = u64_max(moqtsw_next(ot), moqtsw_next(t));
  moqtsw_new_side(ops, t, s, g);
  s->sw_peer_rid = a->request_id; /* B names A: moqtsw_orphan */
  moqtsw_old_side(hub, a, s, sw, g);
  ops->remember(hub, a);
  hub->sw_live++;
}

void moqtsw_begin(
    wired_moqt_hub*      hub,
    const moqtsw_ops*    ops,
    wired_moqtrun_track* t,
    wired_moqtrun_sub*   s,
    const moqctl_params* params) {
  const moqctl_param* p = moqtsw_param(params);
  if (p) {
    moqtsw_start(hub, ops, t, s, &p->sw);
  }
}
