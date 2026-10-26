#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_rel_tick_relay(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    u64                  now_ms);
static void moqtrun_rel_tick_track(
    wired_moqt_hub* hub, wired_moqtrun_track* track, u64 now_ms);
static void moqtrun_rel_tick_peer(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 now_ms);
static void moqtrun_relay_continue_lossy(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           whole,
    moqdata_objseq       seq0,
    int                  fin,
    u64                  born_ms);
static void moqtrun_relay_forward(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           whole,
    moqdata_objseq       seq0,
    int                  fin,
    u64                  born_ms);

/* wired_moqt_tick's reliable-relay walk: drain every ring-backed relay so
 * refused rounds retry, stalls shed, and holds release on the clock, not
 * only when the publisher happens to deliver again. */
static void moqtrun_rel_tick_relay(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    u64                  now_ms) {
  if (!relay->in_use || relay->rel_idx < 0) {
    return;
  }
  moqtrun_rel_drain_one(
      hub, track, relay, &hub->rel_pool[relay->rel_idx], now_ms);
}

static void moqtrun_rel_tick_track(
    wired_moqt_hub* hub, wired_moqtrun_track* track, u64 now_ms) {
  if (!track->in_use) {
    return;
  }
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++) {
    moqtrun_rel_tick_relay(hub, track, &track->relays[r], now_ms);
  }
}

static void moqtrun_rel_tick_peer(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 now_ms) {
  if (!p->in_use) {
    return;
  }
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++) {
    moqtrun_rel_tick_track(hub, &p->tracks[t], now_ms);
  }
}

void moqtrun_rel_tick_all(wired_moqt_hub* hub, u64 now_ms) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    moqtrun_rel_tick_peer(hub, &hub->peers[i], now_ms);
  }
}

/* ============== end of the reliable-relay (moqtrel) block ============== */

/* The pre-existing drop-on-refusal continue, byte-for-byte: forward the
 * round and free the entry at the publisher's FIN. */
static void moqtrun_relay_continue_lossy(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           whole,
    moqdata_objseq       seq0,
    int                  fin,
    u64                  born_ms) {
  if (moqtrun_relay_round_due(whole, fin)) {
    moqtrun_relay_append_all(hub, track, relay, whole, seq0, fin, born_ms);
  }
  if (fin) {
    relay->in_use = 0;
  }
}

/* A later call on an already-relayed publisher stream: forward its
 * whole-Object bytes (moqtrun_relay_normalize) to every subscriber-side
 * stream this relay opened, and free the entry once the publisher's FIN
 * has been forwarded (the subscriber streams are closed by that same
 * round; a fragment still held at FIN time is a torn tail with no
 * continuation coming -- dropped). A ring-backed relay (rel_idx >= 0)
 * takes the reliable path instead: its bytes are retried, not dropped,
 * and its entry lives until every cursor is delivered or given up; both
 * cut each round at the subscriber's start and End Objects. */
static void moqtrun_relay_forward(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           whole,
    moqdata_objseq       seq0,
    int                  fin,
    u64                  born_ms) {
  moqtrun_sgt_arm(hub, track, relay, fin);
  if (relay->rel_idx >= 0) {
    moqtrun_rel_continue(hub, track, relay, whole, seq0, fin, born_ms);
    return;
  }
  moqtrun_relay_continue_lossy(hub, track, relay, whole, seq0, fin, born_ms);
}

/* A poisoned relay only absorbs its publisher's bytes, so they never get
 * re-classified as a fresh stream, and frees at the publisher's FIN. */
void moqtrun_relay_sink(wired_moqtrun_relay* relay, int fin) {
  if (fin) {
    relay->in_use = 0;
  }
}

/* The round that poisoned relay (moqtrun_frag_drop) ends its subscriber
 * side the way an abandoned relay stream ends (moqtrun_relay_reset_stale):
 * every subscriber stream is reset and a bound ring returned, so no
 * subscriber reads past the last whole Object. */
void moqtrun_relay_end_poisoned(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    int                  fin) {
  if (!moqtrun_relay_poisoned(relay)) {
    return;
  }
  moqtrun_relay_reset_stale(hub, track, relay);
  moqtrun_relay_return_ring(hub, relay);
  moqtrun_relay_sink(relay, fin);
}

void moqtrun_relay_continue(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           wire,
    int                  fin) {
  if (moqtrun_relay_poisoned(relay)) {
    moqtrun_relay_sink(relay, fin);
    return;
  }
  u64            born_ms;
  moqdata_objseq seq0;
  wired_span     whole =
      moqtrun_relay_normalize(hub, track, relay, wire, &born_ms, &seq0);
  /* A FIN while a torn Object is held (draft-19 11.4: FIN mid-Object). */
  moqtrun_rx_flag(hub, fin && relay->frag_len != 0);
  /* Objects completed before the dropped tail are sound: deliver them,
   * then end the subscriber streams (moqtrun_relay_end_poisoned). */
  moqtrun_relay_forward(hub, track, relay, whole, seq0, fin, born_ms);
  moqtrun_relay_end_poisoned(hub, track, relay, fin);
}

/* Opened stream sid on relay's sub slot i reached an End Object mid-open
 * (moqtrun_relay_open_one's cut shorter than its own wire): nothing more
 * will ever be sent on it, so it is FIN'd right away and i marked expired
 * (moqtrun_relay_skips) so no later round reopens or appends to it. */
void moqtrun_relay_open_end_hit(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    u64                  sid,
    wired_moqtrun_relay* relay,
    usz                  i,
    usz                  cut_n,
    usz                  wire_n) {
  if (cut_n == wire_n) {
    return;
  }
  hub->io.stream_fin(wt, sid);
  relay->sub_expired |= moqtrun_sub_bit(i);
}

/* relay is lossy and its Group past every Group sub was opened a lossy
 * stream in. */
int moqtrun_relay_newer_for(
    const wired_moqtrun_sub* sub, const wired_moqtrun_relay* relay) {
  return relay->rel_idx < 0 &&
         (!sub->newest_sid || relay->group_id > sub->newest_group);
}
