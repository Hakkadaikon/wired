#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_live_send_one(wired_moqt_hub* hub, usz i, u64 g);
static void moqtrun_live_serve_sub(wired_moqt_hub* hub, usz i, u64 g);
static void moqtrun_live_tick(wired_moqt_hub* hub, u64 now_ms);

/* Sends Group g to sub slot i; on acceptance counts any skipped Groups
 * and records g. A refused send records nothing (retried next tick while
 * the clock is still in g). */
static void moqtrun_live_send_one(wired_moqt_hub* hub, usz i, u64 g) {
  wired_moqtrun_live* live = &hub->live;
  wired_moqtrun_peer* dst  = &hub->peers[live->track.subs[i].session_idx];
  wired_span          frag = live->frags[g % live->n_frags];
  u8                  head[MOQDATA_MSG_OVERHEAD];
  usz                 hn = moqtrun_live_head(live, g, frag.n, head);
  if (!moqtrun_live_due(hub, dst, i, g)) {
    return;
  }
  if (hub->io.send_uni2(dst->wt, wired_span_of(head, hn), frag) < 0) {
    return;
  }
  live->track.subs[i].stream_count++;
  hub->stat_live_drop += moqtrun_live_gap(live, i, g);
  live->sent_group[i] = g;
  live->sent_any[i]   = 1;
  hub->stat_live_sent++;
}

static void moqtrun_live_serve_sub(wired_moqt_hub* hub, usz i, u64 g) {
  if (!moqtrun_sub_forwards(&hub->live.track.subs[i])) {
    return;
  }
  if (!moqtrun_live_owes(&hub->live, i, g)) {
    return;
  }
  moqtrun_live_send_one(hub, i, g);
}

/* The hub's own live track: the Group current at now_ms to every
 * subscriber behind it. */
static void moqtrun_live_tick(wired_moqt_hub* hub, u64 now_ms) {
  if (!hub->live.track.in_use) {
    return;
  }
  u64 g = moqtrun_live_group_at(&hub->live, now_ms);
  moqtrun_track_note(&hub->live.track, g, 0);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    moqtrun_live_serve_sub(hub, i, g);
  }
}

void wired_moqt_tick(wired_moqt_hub* hub, u64 now_ms) {
  hub->live.last_now_ms = now_ms;
  moqtrun_fetches_tick(hub, 0); /* ascending backlog before live rounds */
  moqtrun_rel_tick_all(hub, now_ms);
  moqtrun_drain_tick(hub, now_ms);
  moqtrun_pubdone_sweep(hub);
  moqtrun_rdv_tick(hub, now_ms);
  moqtrun_reqs_tick(hub);
  moqtrun_live_tick(hub, now_ms);
  moqtss_tick(hub, now_ms);
  moqtrun_fetches_tick(hub, 1); /* a descending fill waits for them */
}

/* Records slot for peer_idx, replies SUBSCRIBE_OK with the live track's
 * own alias, and sends the Group current at the last tick at once (its
 * fragment starts with a keyframe). The subscription's Location Filter
 * start still gates that send (moqtrun_live_due, 5.1.4): a start behind
 * the live edge is effectively clamped to the current Group, a future
 * start keeps the attach silent until the clock reaches it. */
void moqtrun_live_attach(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    wired_moqtrun_sub*      slot,
    usz                     peer_idx,
    const moqctl_subscribe* m) {
  usz i = (usz)(slot - hub->live.track.subs);
  moqtrun_sub_open(
      slot, &hub->live.track, peer_idx, hub->live.track.own_alias, m);
  hub->live.sent_any[i] = 0;
  moqtrun_queue_subscribe_ok(p, &hub->live.track, slot);
  if (moqtrun_sub_forwards(slot)) {
    moqtrun_live_send_one(
        hub, i, moqtrun_live_group_at(&hub->live, hub->live.last_now_ms));
  }
}
