#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_rel_send_ring(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u64                  now_ms);
static void moqtrun_rel_send_lead(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u64                  now_ms);
static void moqtrun_rel_send_round(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u64                  now_ms);

/* One send round for cursor i: the ring's next contiguous span, deferred
 * whole while the session's credit cannot spare it, the FIN riding the
 * last one. A refusal or deferral changes nothing -- the same span
 * retries on a later tick (delayed, never dropped). */
static void moqtrun_rel_send_ring(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u64                  now_ms) {
  wired_span span = moqtrun_rel_next(rb, i);
  if (span.n == 0) { /* caught up: only the FIN can remain */
    moqtrun_rel_try_fin(hub, wt, relay, rb, i);
    return;
  }
  if (moqtrun_rel_budget_wait(hub, wt, span.n)) return;
  moqtrun_rel_send_span(hub, wt, relay, rb, i, span, now_ms);
}

/* Cursor i's re-framed Object ID (lead_id) in place of the ID Delta at
 * its cursor, as a round of its own; the Object's rest follows from the
 * ring. A refusal changes nothing. */
static void moqtrun_rel_send_lead(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u64                  now_ms) {
  u8           v[16];
  moqtrel_sub* c = &rb->subs[i];
  usz          n = moqvi_encode(v, c->lead_id);
  if (hub->io.stream_send(
          wt, relay->sub_stream_id[i], wired_span_of(v, n), 0) != 1) {
    hub->stat_rel_refused++;
    return;
  }
  hub->stat_rel_sent++;
  moqtrel_note_sent(rb, (u32)i, c->lead_skip, now_ms);
  c->lead_skip = 0;
}

/* One send round for cursor i: a pending re-framed Object ID first
 * (moqtrun_rel_send_lead), then -- unless that was refused -- the ring's
 * bytes (moqtrun_rel_send_ring). */
static void moqtrun_rel_send_round(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u64                  now_ms) {
  if (rb->subs[i].lead_skip)
    moqtrun_rel_send_lead(hub, wt, relay, rb, i, now_ms);
  if (!rb->subs[i].lead_skip)
    moqtrun_rel_send_ring(hub, wt, relay, rb, i, now_ms);
}

/* Cursor i's whole drain turn: skip one with nothing to do or a vanished
 * destination, shed a stalled one, send one round otherwise. */
void moqtrun_rel_drain_sub(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u64                  now_ms) {
  wired_moqtrun_peer* dst = moqtrun_rel_sub_dst(hub, track, rb, i);
  if (!dst) return;
  int code = moqtrun_rel_give_up(track, relay, rb, i, now_ms);
  if (code != MOQTRUN_REL_KEEP) {
    moqtrun_rel_shed(hub, dst->wt, relay, rb, i, (u32)code);
    return;
  }
  moqtrun_rel_send_round(hub, dst->wt, relay, rb, i, now_ms);
}

/* Backpressure release: enough drained -- give the publisher its credit
 * back. held is only ever set through a non-null stream_hold (the gate
 * in moqtrun_rel_start), so no null check is needed. */
void moqtrun_rel_maybe_release(wired_moqt_hub* hub, moqtrel_buf* rb) {
  if (!rb->held || !moqtrel_should_release(rb)) return;
  hub->io.stream_hold(rb->pub, rb->pub_stream, 0);
  rb->held = 0;
}

/* Returns the ring to the pool. A still-applied hold is released first --
 * an all-shed ring can finish while the publisher still sends, and its
 * receive credit must not stay frozen forever. */
void moqtrun_rel_return_ring(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, moqtrel_buf* rb) {
  if (rb->held) hub->io.stream_hold(rb->pub, rb->pub_stream, 0);
  rb->in_use     = 0;
  relay->rel_idx = -1;
}
