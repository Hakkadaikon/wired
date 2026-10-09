#include "app/moqt/run/moqtswitch.h"

#include "common/bytes/util/num.h"

/* SWITCH_FROM hub side: moqtswitch.h's file doc. TS-n cite the model's
 * requirements (tasks/loopeng/moqt/TrackSwitch/design.md). */

void moqtsw_sub_clear(wired_moqtrun_sub* s) {
  s->sw_role     = MOQTSW_ROLE_NONE;
  s->sw_mode     = 0;
  s->sw_done     = 0;
  s->sw_g        = 0;
  s->sw_peer_rid = 0;
  s->sw_deadline = 0;
}

static const moqctl_param* moqtsw_param(const moqctl_params* params) {
  return moqctl_params_find(params, MOQCTL_PARAM_SWITCH_FROM);
}

/* s is switching away already (a second switch from it is refused). */
static int moqtsw_pending(const wired_moqtrun_sub* s) {
  return s && s->sw_role == MOQTSW_ROLE_OLD;
}

/* s is a switching-set member (SSTS, moqtssts_run.c): SWITCH_FROM and
 * SSTS are not combined. Reads the field W4b's moqtss_sub_in_set reads,
 * keeping this module free of moqtssts_run.c symbols. */
static int moqtsw_in_set(const wired_moqtrun_sub* s) { return s && s->ssts_on; }

/* s may take part in a switch: not already switching away, in no set. */
static int moqtsw_free(const wired_moqtrun_sub* s) {
  return !moqtsw_pending(s) && !moqtsw_in_set(s);
}

/* ===================== validation (TS-9) ===================== */

/* The activating side of one check: session idx, its subscription self
 * (0 for a SUBSCRIBE) under Request ID rid on track t, and held -- a
 * subscription the session already has on t (SUBSCRIBE only). */
typedef struct {
  usz                        idx;
  const wired_moqtrun_track* t;
  const wired_moqtrun_sub*   self;
  const wired_moqtrun_sub*   held;
  u64                        rid;
} moqtsw_req;

static int moqtsw_hub_track(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  return t == &hub->blob_track || t == &hub->live.track;
}

/* The activating side can take a switch: a live peer track the session
 * does not hold yet, itself not switching away. */
static int moqtsw_peer_track(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  return t && !moqtsw_hub_track(hub, t);
}

static int moqtsw_target_ok(const wired_moqt_hub* hub, const moqtsw_req* r) {
  return moqtsw_peer_track(hub, r->t) && !r->held && moqtsw_free(r->self);
}

/* The named subscription can be stopped: live, on another track, not
 * switching away already, in no switching set. */
static int moqtsw_old_ok(
    const wired_moqtrun_sub*   old,
    const wired_moqtrun_track* ot,
    const wired_moqtrun_track* t) {
  return old && ot != t && moqtsw_free(old);
}

static int moqtsw_valid(
    wired_moqt_hub*          hub,
    const moqtsw_ops*        ops,
    const moqtsw_req*        r,
    const moqctl_switchfrom* sw) {
  wired_moqtrun_track* ot = 0;
  if (sw->request_id == r->rid || !moqtsw_target_ok(hub, r)) return 0;
  return moqtsw_old_ok(ops->find(hub, r->idx, sw->request_id, &ot), ot, r->t);
}

/* Parameters a SWITCH_FROM cannot share a message with: FORWARD (the
 * switch decides the activating side's Forward State itself, moqtail
 * plan_switch), FILL_PARAMETERS (a fill delivers Groups below G: NoDup)
 * and SWITCHING_SET_ASSIGNMENT (SSTS and SWITCH_FROM are not combined). */
static const u64 MOQTSW_CONFLICTS[] = {
    MOQCTL_PARAM_FORWARD, MOQCTL_PARAM_FILL_PARAMETERS,
    MOQCTL_PARAM_SWITCHING_SET_ASSIGNMENT};

static int moqtsw_conflict(const moqctl_params* params) {
  for (usz i = 0; i < sizeof MOQTSW_CONFLICTS / sizeof MOQTSW_CONFLICTS[0]; i++)
    if (moqctl_params_find(params, MOQTSW_CONFLICTS[i])) return 1;
  return 0;
}

static u64 moqtsw_shape(
    wired_moqt_hub*          hub,
    const moqtsw_ops*        ops,
    const moqtsw_req*        r,
    const moqctl_params*     params,
    const moqctl_switchfrom* sw) {
  if (moqtsw_conflict(params)) return MOQCTL_ERR_INVALID_SWITCH;
  return moqtsw_valid(hub, ops, r, sw) ? MOQTSW_ACCEPT
                                       : MOQCTL_ERR_INVALID_SWITCH;
}

static u64 moqtsw_verdict(
    wired_moqt_hub*      hub,
    const moqtsw_ops*    ops,
    const moqtsw_req*    r,
    const moqctl_params* params) {
  const moqctl_param* p = moqtsw_param(params);
  return p ? moqtsw_shape(hub, ops, r, params, &p->sw) : MOQTSW_ACCEPT;
}

/* SWITCH_FROM present while switching is off. */
static int moqtsw_off(const wired_moqt_hub* hub, const moqctl_params* params) {
  return !hub->switch_track && moqtsw_param(params);
}

int moqtsw_take(const wired_moqt_hub* hub, int r, const moqctl_params* params) {
  if (r != MOQCTL_OK) return r;
  return moqtsw_off(hub, params) ? MOQCTL_VIOLATION : MOQCTL_OK;
}

u64 moqtsw_pub_refusal(const moqctl_params* params, u64 prior) {
  if (prior != MOQTSW_ACCEPT) return prior;
  return moqtsw_param(params) ? MOQCTL_ERR_INVALID_SWITCH : MOQTSW_ACCEPT;
}

u64 moqtsw_sub_refusal(const moqctl_params* params, int hub_track, u64 prior) {
  if (prior != MOQTSW_ACCEPT) return prior;
  return hub_track ? moqtsw_pub_refusal(params, prior) : MOQTSW_ACCEPT;
}

u64 moqtsw_check(
    wired_moqt_hub*            hub,
    const moqtsw_ops*          ops,
    usz                        idx,
    const wired_moqtrun_track* t,
    const wired_moqtrun_sub*   held,
    u64                        rid,
    const moqctl_params*       params) {
  moqtsw_req r = {idx, t, 0, held, rid};
  return moqtsw_verdict(hub, ops, &r, params);
}

u64 moqtsw_upd_check(
    wired_moqt_hub*            hub,
    const moqtsw_ops*          ops,
    usz                        idx,
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params) {
  moqtsw_req r = {idx, t, s, 0, s ? s->request_id : 0};
  return moqtsw_verdict(hub, ops, &r, params);
}

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
  if (moqtsw_ends_by(s, e)) return;
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
  if (moqctl_loc_less(s->start, g)) s->start = g;
}

static void (*const MOQTSW_BOUND_FNS[])(wired_moqtrun_sub*) = {
    moqtsw_bound_none, moqtsw_bound_old, moqtsw_bound_new};

void moqtsw_rebound(wired_moqtrun_sub* s) { MOQTSW_BOUND_FNS[s->sw_role](s); }

void moqtsw_reattached(wired_moqt_hub* hub, wired_moqtrun_sub* s) {
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
  if (!a) return; /* checked in this same dispatch: cannot happen */
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
  if (p) moqtsw_start(hub, ops, t, s, &p->sw);
}

/* ===================== ending A (TS-3..TS-8) ===================== */

/* Relay r may still deliver to slot si (A, ending at G-1): it is live
 * on a Group below G and si's stream was not given up for it -- whether
 * or not si's stream is open right now (a refused open, or a busy shed,
 * re-opens on a later round; moqtrun_pubdone_relaying's rule). */
static int moqtsw_relay_owes(
    const wired_moqtrun_relay* r, const wired_moqtrun_sub* a, usz si) {
  return r->in_use && r->group_id < a->sw_g &&
         !(r->sub_expired & ((u32)1 << si));
}

/* Something of A's Groups below G may still reach slot si on t. */
static int moqtsw_open(const wired_moqtrun_track* t, usz si) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++)
    if (moqtsw_relay_owes(&t->relays[r], &t->subs[si], si)) return 1;
  return 0;
}

/* A's track reached G-1: every A group below G has opened (groups open
 * in order per track, the model's assumption). */
static int moqtsw_progressed(
    const wired_moqtrun_track* t, const wired_moqtrun_sub* s) {
  return t->has_largest && t->largest.group + 1 >= s->sw_g;
}

static int moqtsw_soft_ready(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_track* t,
    const wired_moqtrun_sub*   s) {
  return moqtsw_progressed(t, s) || hub->live.last_now_ms >= s->sw_deadline;
}

/* TS-3: A's G-1 stream FINned (or the deadline passed) and nothing of A
 * is open -- PUBLISH_DONE never precedes A's last stream. */
static int moqtsw_soft_due(
    wired_moqt_hub*      hub,
    const moqtsw_ops*    ops,
    wired_moqtrun_track* t,
    usz                  si) {
  (void)ops;
  return !moqtsw_open(t, si) && moqtsw_soft_ready(hub, t, &t->subs[si]);
}

/* t (B's track) reached Group g: its stream or datagram of g has
 * arrived, and was relayed to B in that same dispatch. */
static int moqtsw_reached(const wired_moqtrun_track* t, u64 g) {
  return t->has_largest && t->largest.group >= g;
}

/* TS-4: B's track reached G (stream or datagram), or B is gone
 * (cancelled, ended) -- the cut then happens now, never leaking A. */
static int moqtsw_hard_due(
    wired_moqt_hub*      hub,
    const moqtsw_ops*    ops,
    wired_moqtrun_track* t,
    usz                  si) {
  const wired_moqtrun_sub* a  = &t->subs[si];
  wired_moqtrun_track*     bt = 0;
  const wired_moqtrun_sub* b =
      ops->find(hub, a->session_idx, a->sw_peer_rid, &bt);
  return !b || moqtsw_reached(bt, a->sw_g);
}

typedef int (*moqtsw_due_fn)(
    wired_moqt_hub*, const moqtsw_ops*, wired_moqtrun_track*, usz);

/* Indexed by sw_mode: 0 Hard, 1 Soft. */
static const moqtsw_due_fn MOQTSW_DUE_FNS[] = {
    moqtsw_hard_due, moqtsw_soft_due};

static int moqtsw_due(
    wired_moqt_hub*      hub,
    const moqtsw_ops*    ops,
    wired_moqtrun_track* t,
    usz                  si) {
  const wired_moqtrun_sub* a = &t->subs[si];
  return !a->sw_g || MOQTSW_DUE_FNS[a->sw_mode](hub, ops, t, si);
}

/* No Publish Done: suspended like moqtail -- streams reset, FORWARD 0,
 * the subscription (and its request stream) stays. */
static void moqtsw_suspend(
    wired_moqt_hub*      hub,
    const moqtsw_ops*    ops,
    wired_moqtrun_track* t,
    usz                  si) {
  ops->stop_streams(hub, t, si);
  t->subs[si].forward_off = 1;
  ops->remember(hub, &t->subs[si]);
}

static void moqtsw_publish_done(
    wired_moqt_hub*      hub,
    const moqtsw_ops*    ops,
    wired_moqtrun_track* t,
    usz                  si) {
  ops->done(hub, t, si);
}

typedef void (*moqtsw_end_fn)(
    wired_moqt_hub*, const moqtsw_ops*, wired_moqtrun_track*, usz);

/* Indexed by sw_done. */
static const moqtsw_end_fn MOQTSW_END_FNS[] = {
    moqtsw_suspend, moqtsw_publish_done};

/* b is the subscription A's switch activated, still marked so. */
static int moqtsw_new_of(
    const wired_moqtrun_sub* b, const wired_moqtrun_sub* a) {
  return b && b->sw_role == MOQTSW_ROLE_NEW && b->sw_g == a->sw_g;
}

/* A ended: B's start clamp has done its job -- a later filter update or
 * re-attach of B resolves from B's own filter again. */
static void moqtsw_release_new(
    wired_moqt_hub* hub, const moqtsw_ops* ops, const wired_moqtrun_sub* a) {
  wired_moqtrun_track* bt = 0;
  wired_moqtrun_sub*   b  = ops->find(hub, a->session_idx, a->sw_peer_rid, &bt);
  if (!moqtsw_new_of(b, a)) return;
  b->sw_role = MOQTSW_ROLE_NONE;
  ops->remember(hub, b);
}

/* 1 when A ended now. */
static int moqtsw_try(
    wired_moqt_hub*      hub,
    const moqtsw_ops*    ops,
    wired_moqtrun_track* t,
    usz                  si) {
  wired_moqtrun_sub* a = &t->subs[si];
  /* A withdrawn track waits for its re-PUBLISH (the re-attached A keeps
   * its switch, moqtsw_rebound). */
  if (!t->in_use || !moqtsw_due(hub, ops, t, si)) return 0;
  a->sw_role = MOQTSW_ROLE_NONE;
  moqtsw_release_new(hub, ops, a);
  MOQTSW_END_FNS[a->sw_done](hub, ops, t, si);
  return 1;
}

/* A subscription (TS-5/7/8: still active -- an A already ended by its
 * publisher, a cancel or a session close is skipped) waiting to end. */
static int moqtsw_waiting(const wired_moqtrun_sub* s) {
  return s->active && s->sw_role == MOQTSW_ROLE_OLD;
}

/* a carries B's A identity: B's peer Request ID, OLD, same boundary. */
static int moqtsw_old_match(
    const wired_moqtrun_sub* a, const wired_moqtrun_sub* b) {
  return a->request_id == b->sw_peer_rid && a->sw_role == MOQTSW_ROLE_OLD &&
         a->sw_g == b->sw_g;
}

/* a is B's A, still switching away at B's boundary. */
static int moqtsw_old_of(
    const wired_moqtrun_sub* a, const wired_moqtrun_sub* b) {
  return a->active && a->session_idx == b->session_idx &&
         moqtsw_old_match(a, b);
}

/* b is an active B of a switch. */
static int moqtsw_is_new(const wired_moqtrun_sub* b) {
  return b->active && b->sw_role == MOQTSW_ROLE_NEW;
}

static int moqtsw_old_on_track(
    const wired_moqtrun_track* t, const wired_moqtrun_sub* b) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (moqtsw_old_of(&t->subs[i], b)) return 1;
  return 0;
}

/* Any track slot of p, withdrawn ones included: A on a track awaiting
 * its re-PUBLISH keeps its switch (moqtsw_try). */
static int moqtsw_old_on_peer(
    const wired_moqtrun_peer* p, const wired_moqtrun_sub* b) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    if (moqtsw_old_on_track(&p->tracks[t], b)) return 1;
  return 0;
}

static int moqtsw_peer_holds_old(
    const wired_moqtrun_peer* p, const wired_moqtrun_sub* b) {
  return p->in_use && moqtsw_old_on_peer(p, b);
}

static int moqtsw_old_alive(
    const wired_moqt_hub* hub, const wired_moqtrun_sub* b) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (moqtsw_peer_holds_old(&hub->peers[i], b)) return 1;
  return 0;
}

/* A ended some other way than its switch (cancelled, its publisher's
 * PUBLISH_DONE / TRACK_ENDED, its publisher's session gone): B's start
 * clamp is released too, so B may later switch again or join a
 * switching set (moqtsw_release_new's twin, from B's side). */
static void moqtsw_orphan(
    wired_moqt_hub* hub, const moqtsw_ops* ops, wired_moqtrun_sub* b) {
  if (!moqtsw_is_new(b) || moqtsw_old_alive(hub, b)) return;
  b->sw_role = MOQTSW_ROLE_NONE;
  ops->remember(hub, b);
}

static int moqtsw_visit(
    wired_moqt_hub*      hub,
    const moqtsw_ops*    ops,
    wired_moqtrun_track* t,
    usz                  si,
    u32*                 live) {
  moqtsw_orphan(hub, ops, &t->subs[si]);
  if (!moqtsw_waiting(&t->subs[si])) return 0;
  int ended = moqtsw_try(hub, ops, t, si);
  *live += (u32)!ended;
  return ended;
}

static int moqtsw_step_track(
    wired_moqt_hub*      hub,
    const moqtsw_ops*    ops,
    wired_moqtrun_track* t,
    u32*                 live) {
  int n = 0;
  for (usz si = 0; si < WIRED_MOQTRUN_MAX_SUBS; si++)
    n += moqtsw_visit(hub, ops, t, si, live);
  return n;
}

static int moqtsw_step_peer(
    wired_moqt_hub*     hub,
    const moqtsw_ops*   ops,
    wired_moqtrun_peer* p,
    u32*                live) {
  int n = 0;
  if (!p->in_use) return 0;
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    n += moqtsw_step_track(hub, ops, &p->tracks[t], live);
  return n;
}

/* hub->sw_live is a hint (switches begun since the last sweep, plus the
 * ones it left waiting): 0 skips the walk, each walk recounts it. */
int moqtsw_step(wired_moqt_hub* hub, const moqtsw_ops* ops) {
  int n    = 0;
  u32 live = 0;
  if (!hub->sw_live) return 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    n += moqtsw_step_peer(hub, ops, &hub->peers[i], &live);
  hub->sw_live = live;
  return n;
}

u64 moqtsw_done_code(int ver, u64 status) {
  return status == MOQTSW_DONE_SWITCHED ? MOQCTL_DONE_SWITCHED
                                        : moqctl_publish_done_for(ver, status);
}
