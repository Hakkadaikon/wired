#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_relay_save_hdr(wired_moqtrun_relay* relay, wired_span data);
static void moqtrun_relay_claim_init(
    wired_moqtrun_relay*       relay,
    const wired_moqtrun_track* track,
    u64                        pub_stream_id);
static void moqtrun_relay_head_init(
    wired_moqt_hub*      hub,
    wired_moqtrun_relay* relay,
    wired_span           wire,
    usz                  whole_end);

/* The stream's Subgroup ID and Publisher Priority kept for late opens and
 * the Range Filter gate (moqtrun_stream_keys). ponytail: a mode-0b01
 * stream whose first delivery tore inside its first Object saves no
 * header, so late joiners of that stream are skipped; resolve it on the
 * next delivery if that matters. */
static void moqtrun_relay_save_hdr(
    wired_moqtrun_relay* relay, wired_span data) {
  usz            off = 0;
  moqdata_subhdr hdr;
  relay->hdr_len = 0;
  if (!moqtrun_stream_keys(
          data, relay->default_pub_prio, &relay->subgroup_id,
          &relay->pub_prio)) {
    return;
  }
  (void)moqdata_subhdr_take(data, &off, &hdr); /* stream_keys decoded it */
  moqtrun_relay_save_hdr_raw(relay, data, off);
}

/* Starts relaying a fresh publisher stream that stays open past this call
 * (fin=0): claims a relay entry keyed by pub_stream_id and opens one
 * keep-open uni stream per subscriber carrying wire as the first round.
 * Every entry busy -> this stream is not relayed at all (its subscribers
 * miss it; WIRED_MOQTRUN_MAX_RELAYS is sized so this only happens under a
 * burst the room's own pacing never produces). A reliable track's stream
 * (moqtrun_rel_start) additionally binds a ring and records each opened
 * subscriber stream as a ring cursor (moqtrun_rel_attach_subs); the open
 * calls themselves are shared with the lossy path. */
/* A just-claimed relay entry for pub_stream_id, lossy and with no
 * subscriber stream open yet. */
static void moqtrun_relay_claim_init(
    wired_moqtrun_relay*       relay,
    const wired_moqtrun_track* track,
    u64                        pub_stream_id) {
  relay->in_use           = 1;
  relay->default_pub_prio = track->default_pub_prio;
  relay->pub_stream_id    = pub_stream_id;
  relay->rel_idx          = -1; /* lossy until moqtrun_rel_start binds a ring */
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    relay->sub_stream_set[i]  = 0;
    relay->sub_busy_streak[i] = 0; /* freestanding memory starts unzeroed */
    relay->sub_part[i]        = 0;
  }
  moqtrun_frag_release(relay);
}

/* relay's per-stream state from its first delivery wire, whole Objects up
 * to whole_end: the held tail and the saved SUBGROUP_HEADER. */
static void moqtrun_relay_head_init(
    wired_moqt_hub*      hub,
    wired_moqtrun_relay* relay,
    wired_span           wire,
    usz                  whole_end) {
  relay->sub_expired = 0;
  relay->sub_reframe = 0;
  relay->subgroup_id = 0;
  relay->pub_prio    = relay->default_pub_prio;
  moqtrun_relay_save_frag(
      hub, relay, wire.p + whole_end, wire.n - whole_end,
      hub->live.last_now_ms);
  moqtrun_relay_save_hdr(relay, wire);
}

void moqtrun_relay_start(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_wt_session*    pub_wt,
    u64                  pub_stream_id,
    wired_span           wire,
    usz                  whole_end) {
  wired_moqtrun_relay* relay = moqtrun_relay_alloc(track);
  if (!relay) {
    hub->stat_relay_full++; /* whole message lost for every subscriber */
    return;
  }
  moqtrun_relay_claim_init(relay, track, pub_stream_id);
  if (whole_end == 0) { /* starts at a nonexistent Object (moqtrun_gone.c) */
    relay->frag_idx = MOQTRUN_FRAG_POISONED;
    return;
  }
  moqtrun_rel_start(
      hub, track, relay, pub_wt, pub_stream_id,
      wired_span_of(wire.p, whole_end));
  moqtrun_relay_head_init(hub, relay, wire, whole_end);
  moqtrun_subgroup_scan(
      wired_span_of(wire.p, whole_end), 0, &relay->seq, &relay->group_id);
  relay->dseq = relay->seq;
  moqtss_prime(hub, track, relay->group_id); /* SSTS (moqtssts_run.c) */
  moqtrun_relay_open_all(hub, track, relay, wired_span_of(wire.p, whole_end));
  moqtrun_rel_attach_subs(hub, track, relay);
  moqtrun_cut_push(hub, track, relay); /* draft-18 5.1 */
  moqtrun_relay_end_poisoned(hub, track, relay, 0);
}
