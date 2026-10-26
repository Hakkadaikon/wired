#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_sgt_wants(
    const wired_moqtrun_relay* relay, const wired_moqtrun_sub* sub, usz i);
static void moqtrun_sgt_put(
    wired_moqt_hub* hub, wired_wt_session* wt, u64 sid, u64 deadline_ms);
static void moqtrun_sgt_arm_all(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* track,
    const wired_moqtrun_relay* relay);
static int moqtrun_sgt_due(const wired_moqtrun_sgt* e, u64 now_ms);
static int moqtrun_sgt_uncommitted(
    const wired_moqt_hub* hub, const wired_moqtrun_sgt* e);
static void moqtrun_sgt_fire(wired_moqt_hub* hub, wired_moqtrun_sgt* e);

/* ===== SUBGROUP_DELIVERY_TIMEOUT after the upstream FIN =====
 * draft-19 8 (draft-18 8, draft-22 5.2): with a non-zero timeout "the
 * MOQT implementation MUST start a timer ... once it becomes aware that
 * all of the objects on the subgroup have been published (either by
 * receiving a FIN from the upstream subscription ...)"; a stream that
 * has not reached "all data committed" when it expires is reset. The
 * relay's upstream FIN arms one timer per downstream stream; the tick
 * resets those still unacknowledged (io.stream_inflight). */

/* Sub slot i of relay has a downstream stream and a timeout. */
static int moqtrun_sgt_wants(
    const wired_moqtrun_relay* relay, const wired_moqtrun_sub* sub, usz i) {
  return relay->sub_stream_set[i] && sub->subgroup_timeout;
}

static void moqtrun_sgt_put(
    wired_moqt_hub* hub, wired_wt_session* wt, u64 sid, u64 deadline_ms) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SGT; i++) {
    if (!hub->sgt[i].in_use) {
      hub->sgt[i] = (wired_moqtrun_sgt){wt, sid, deadline_ms, 1};
      return;
    }
  }
}

/* The publisher's FIN reached relay (fin): every downstream stream of a
 * subscription with a SUBGROUP_DELIVERY_TIMEOUT starts its timer. */
static void moqtrun_sgt_arm_all(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* track,
    const wired_moqtrun_relay* relay) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    const wired_moqtrun_sub* s = &track->subs[i];
    if (moqtrun_sgt_wants(relay, s, i)) {
      moqtrun_sgt_put(
          hub, hub->peers[s->session_idx].wt, relay->sub_stream_id[i],
          hub->live.last_now_ms + s->subgroup_timeout);
    }
  }
}

void moqtrun_sgt_arm(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* track,
    const wired_moqtrun_relay* relay,
    int                        fin) {
  if (fin) {
    moqtrun_sgt_arm_all(hub, track, relay);
  }
}

static int moqtrun_sgt_due(const wired_moqtrun_sgt* e, u64 now_ms) {
  return e->in_use && now_ms >= e->deadline_ms;
}

static int moqtrun_sgt_uncommitted(
    const wired_moqt_hub* hub, const wired_moqtrun_sgt* e) {
  return hub->io.stream_inflight && hub->io.stream_inflight(e->wt, e->sid);
}

static void moqtrun_sgt_fire(wired_moqt_hub* hub, wired_moqtrun_sgt* e) {
  if (moqtrun_sgt_uncommitted(hub, e)) {
    hub->io.stream_reset(e->wt, e->sid, MOQTRUN_RESET_DELIVERY_TIMEOUT);
  }
  e->in_use = 0;
}

void moqtrun_sgt_tick(wired_moqt_hub* hub, u64 now_ms) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SGT; i++) {
    if (moqtrun_sgt_due(&hub->sgt[i], now_ms)) {
      moqtrun_sgt_fire(hub, &hub->sgt[i]);
    }
  }
}
