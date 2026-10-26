#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_rel_maybe_done(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, moqtrel_buf* rb);
static void moqtrun_rel_maybe_hold(wired_moqt_hub* hub, moqtrel_buf* rb);
static void moqtrun_rel_cut_start(
    moqtrel_sub*               c,
    const wired_moqtrun_sub*   sub,
    const wired_moqtrun_relay* relay,
    wired_span                 wire,
    moqdata_objseq             seq,
    u64                        base);
static void moqtrun_rel_cut_all(
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    wired_span           whole,
    moqdata_objseq       seq0,
    u64                  base);

/* Every cursor delivered or given up: the ring returns to the pool. The
 * relay entry frees only once the publisher's FIN was seen; before that
 * it stays bound (rel_idx -1: the lossy continue, which sends nothing
 * with no live subscribers), so the publisher's later deliveries on the
 * same stream keep matching it. Freeing early would re-classify those
 * deliveries as a fresh stream head -- mid-Object bytes decoded as a
 * SUBGROUP_HEADER can resolve to another track's alias and relay garbage
 * to its subscribers. */
static void moqtrun_rel_maybe_done(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, moqtrel_buf* rb) {
  if (!moqtrel_all_done(rb)) {
    return;
  }
  int fin_seen = rb->fin_seen;
  hub->stat_rel_early_return += (u64)!fin_seen;
  moqtrun_rel_return_ring(hub, relay, rb);
  if (fin_seen) {
    relay->in_use = 0;
  }
}

/* One full drain pass over a ring: attach late subscribers, a round per
 * open cursor, reclaim what every live cursor has passed, then the two
 * closing decisions (release the hold once enough drained, return
 * everything once every cursor is delivered or given up). A ring no
 * cursor ever joined skips all three while it awaits a first subscriber
 * (moqtrel_awaits_sub): reclaiming would discard the stream's start.
 * ponytail: a subscriber-less ring may hold its publisher up to
 * WIRED_MOQTREL_STALL_MS; a separate wait budget if that proves long. */
void moqtrun_rel_drain_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    u64                  now_ms) {
  moqtrun_rel_late_attach_all(hub, track, relay, rb, now_ms);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    moqtrun_rel_drain_sub(hub, track, relay, rb, i, now_ms);
  }
  if (moqtrel_awaits_sub(rb, now_ms)) {
    return;
  }
  moqtrel_reclaim(rb);
  moqtrun_rel_maybe_release(hub, rb);
  moqtrun_rel_maybe_done(hub, relay, rb);
}

/* Backpressure hold, decided on the post-drain fill so a round that
 * empties the ring never holds at all. in_use guards the ring
 * moqtrun_rel_maybe_done freed a moment earlier; a bound ring implies a
 * non-null stream_hold (the moqtrun_rel_start gate). */
static void moqtrun_rel_maybe_hold(wired_moqt_hub* hub, moqtrel_buf* rb) {
  if (!rb->in_use || !moqtrel_should_hold(rb)) {
    return;
  }
  hub->io.stream_hold(rb->pub, rb->pub_stream, 1);
  rb->held = 1;
  hub->stat_rel_hold++;
}

/* Cursor c still before its start Object: past every Object of wire (at
 * absolute offset base, chained from seq) that precedes it, the first
 * one at or past it re-framed (moqtrun_rel_lead). */
static void moqtrun_rel_cut_start(
    moqtrel_sub*               c,
    const wired_moqtrun_sub*   sub,
    const wired_moqtrun_relay* relay,
    wired_span                 wire,
    moqdata_objseq             seq,
    u64                        base) {
  if (!c->before_start) {
    return;
  }
  usz off         = moqtrun_startobj_cut(sub, wire, 0, &seq, relay->group_id);
  c->sent         = base + off;
  c->before_start = off == wire.n;
  moqtrun_rel_lead(c, wire, off, seq);
}

/* A round appended at absolute offset base, its Objects chained from
 * seq0: each open cursor's start and End Object cuts (draft-22 3.3.1). */
static void moqtrun_rel_cut_all(
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    wired_span           whole,
    moqdata_objseq       seq0,
    u64                  base) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    if (moqtrun_rel_sub_open(rb, i)) {
      moqtrun_rel_cut_start(
          &rb->subs[i], &track->subs[i], relay, whole, seq0, base);
      moqtrun_rel_cut_end(
          relay, &rb->subs[i], &track->subs[i], i, whole, seq0, base);
    }
  }
}

/* A later delivery on a ring-backed relay: append the whole-Object bytes
 * (the Object-boundary rounding is shared with the lossy path), cut them
 * per cursor (moqtrun_rel_cut_all), record the publisher's FIN, drain
 * this ring now, and decide the hold. */
void moqtrun_rel_continue(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           whole,
    moqdata_objseq       seq0,
    int                  fin,
    u64                  born_ms) {
  moqtrel_buf* rb   = &hub->rel_pool[relay->rel_idx];
  u64          base = rb->tail;
  moqtrun_rel_take(hub, rb, whole, born_ms);
  moqtrun_cut_ring_take(relay, rb, whole.n, hub->live.last_now_ms);
  moqtrun_rel_cut_all(track, relay, rb, whole, seq0, base);
  if (fin) {
    rb->fin_seen = 1;
    hub->stat_rel_fin_in++;
  }
  moqtrun_rel_drain_one(hub, track, relay, rb, hub->live.last_now_ms);
  moqtrun_rel_maybe_hold(hub, rb);
}
