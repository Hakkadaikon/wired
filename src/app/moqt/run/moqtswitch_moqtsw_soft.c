#include "app/moqt/run/moqtswitch_impl.h"

static int moqtsw_relay_owes(
    const wired_moqtrun_relay* r, const wired_moqtrun_sub* a, usz si);
static int moqtsw_open(const wired_moqtrun_track* t, usz si);
static int moqtsw_progressed(
    const wired_moqtrun_track* t, const wired_moqtrun_sub* s);
static int moqtsw_soft_ready(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_track* t,
    const wired_moqtrun_sub*   s);
static int moqtsw_soft_due(
    wired_moqt_hub* hub, const moqtsw_ops* ops, wired_moqtrun_track* t, usz si);
static int moqtsw_reached(const wired_moqtrun_track* t, u64 g);
static int moqtsw_hard_due(
    wired_moqt_hub* hub, const moqtsw_ops* ops, wired_moqtrun_track* t, usz si);
static void moqtsw_suspend(
    wired_moqt_hub* hub, const moqtsw_ops* ops, wired_moqtrun_track* t, usz si);
static void moqtsw_publish_done(
    wired_moqt_hub* hub, const moqtsw_ops* ops, wired_moqtrun_track* t, usz si);

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

/* Indexed by sw_mode: 0 Hard, 1 Soft. */
static const moqtsw_due_fn MOQTSW_DUE_FNS[] = {
    moqtsw_hard_due, moqtsw_soft_due};

int moqtsw_due(
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

/* Indexed by sw_done. */
const moqtsw_end_fn MOQTSW_END_FNS[] = {moqtsw_suspend, moqtsw_publish_done};
