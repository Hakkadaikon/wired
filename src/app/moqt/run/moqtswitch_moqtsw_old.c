#include "app/moqt/run/moqtswitch_impl.h"

static int moqtsw_new_of(
    const wired_moqtrun_sub* b, const wired_moqtrun_sub* a);
static void moqtsw_release_new(
    wired_moqt_hub* hub, const moqtsw_ops* ops, const wired_moqtrun_sub* a);
static int moqtsw_try(
    wired_moqt_hub* hub, const moqtsw_ops* ops, wired_moqtrun_track* t, usz si);
static int moqtsw_waiting(const wired_moqtrun_sub* s);
static int moqtsw_old_match(
    const wired_moqtrun_sub* a, const wired_moqtrun_sub* b);
static int moqtsw_old_of(
    const wired_moqtrun_sub* a, const wired_moqtrun_sub* b);
static int moqtsw_is_new(const wired_moqtrun_sub* b);
static int moqtsw_old_on_track(
    const wired_moqtrun_track* t, const wired_moqtrun_sub* b);
static int moqtsw_old_on_peer(
    const wired_moqtrun_peer* p, const wired_moqtrun_sub* b);
static int moqtsw_peer_holds_old(
    const wired_moqtrun_peer* p, const wired_moqtrun_sub* b);
static int moqtsw_old_alive(
    const wired_moqt_hub* hub, const wired_moqtrun_sub* b);

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
  if (!moqtsw_new_of(b, a)) {
    return;
  }
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
  if (!moqtsw_due(hub, ops, t, si)) {
    return 0;
  }
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
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    if (moqtsw_old_of(&t->subs[i], b)) {
      return 1;
    }
  }
  return 0;
}

/* Any track slot of p, withdrawn ones included: A on a track awaiting
 * its re-PUBLISH keeps its switch (moqtsw_try). */
static int moqtsw_old_on_peer(
    const wired_moqtrun_peer* p, const wired_moqtrun_sub* b) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++) {
    if (moqtsw_old_on_track(&p->tracks[t], b)) {
      return 1;
    }
  }
  return 0;
}

static int moqtsw_peer_holds_old(
    const wired_moqtrun_peer* p, const wired_moqtrun_sub* b) {
  return p->in_use && moqtsw_old_on_peer(p, b);
}

static int moqtsw_old_alive(
    const wired_moqt_hub* hub, const wired_moqtrun_sub* b) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    if (moqtsw_peer_holds_old(&hub->peers[i], b)) {
      return 1;
    }
  }
  return 0;
}

/* A ended some other way than its switch (cancelled, its publisher's
 * PUBLISH_DONE / TRACK_ENDED, its publisher's session gone): B's start
 * clamp is released too, so B may later switch again or join a
 * switching set (moqtsw_release_new's twin, from B's side). */
void moqtsw_orphan(
    wired_moqt_hub* hub, const moqtsw_ops* ops, wired_moqtrun_sub* b) {
  if (!moqtsw_is_new(b) || moqtsw_old_alive(hub, b)) {
    return;
  }
  b->sw_role = MOQTSW_ROLE_NONE;
  ops->remember(hub, b);
}

int moqtsw_visit(
    wired_moqt_hub*      hub,
    const moqtsw_ops*    ops,
    wired_moqtrun_track* t,
    usz                  si,
    u32*                 live) {
  /* A withdrawn track's slots are leftovers: their session_idx may name
   * another client by now. A re-attach recounts and orphan-checks its
   * own copy (moqtsw_reattached). */
  if (!t->in_use) {
    return 0;
  }
  moqtsw_orphan(hub, ops, &t->subs[si]);
  if (!moqtsw_waiting(&t->subs[si])) {
    return 0;
  }
  int ended = moqtsw_try(hub, ops, t, si);
  *live += (u32)!ended;
  return ended;
}
