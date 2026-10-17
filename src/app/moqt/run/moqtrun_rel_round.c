#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_rel_expiry(
    const wired_moqtrun_track* track, const moqtrel_buf* rb, usz i, u64 now_ms);
static int  moqtrun_rel_ends_at(const moqtrel_buf* rb, usz i, u64 at);
static int  moqtrun_rel_round_fins(const moqtrel_buf* rb, usz i, usz n);
static void moqtrun_rel_round_ok(
    wired_moqt_hub* hub,
    moqtrel_buf*    rb,
    usz             i,
    usz             n,
    int             fin_flag,
    u64             now_ms);
static int moqtrun_rel_budget_ok(
    wired_moqt_hub* hub, wired_wt_session* wt, usz n);

/* 0 for a stall, DELIVERY_TIMEOUT once cursor i's next unsent Object
 * reached the hub longer ago than the subscription's
 * OBJECT_DELIVERY_TIMEOUT (draft 8); else MOQTRUN_REL_KEEP. */
static int moqtrun_rel_expiry(
    const wired_moqtrun_track* track,
    const moqtrel_buf*         rb,
    usz                        i,
    u64                        now_ms) {
  if (moqtrel_stalled(rb, (u32)i, now_ms)) return 0;
  if (moqtrun_sub_late(&track->subs[i], moqtrel_age_ms(rb, (u32)i, now_ms)))
    return MOQTRUN_RESET_DELIVERY_TIMEOUT;
  return MOQTRUN_REL_KEEP;
}

/* The reset code to give cursor i up with, else MOQTRUN_REL_KEEP. A
 * subscription that no longer takes this stream (REQUEST_UPDATE turned
 * FORWARD off or moved its Location Filter past the Group) gets nothing
 * appended after the update (10.9.1): CANCELLED, and its cursor stops
 * pinning the ring. */
int moqtrun_rel_give_up(
    const wired_moqtrun_track* track,
    const wired_moqtrun_relay* relay,
    const moqtrel_buf*         rb,
    usz                        i,
    u64                        now_ms) {
  if (!moqtrun_sub_gets_relay(&track->subs[i], relay))
    return MOQTRUN_RESET_CANCELLED;
  return moqtrun_rel_expiry(track, rb, i, now_ms);
}

/* 1 iff cursor i's stream ends at absolute offset at: its End Object
 * cut (moqtrun_rel_cut_end), or the publisher's FIN after the last byte. */
static int moqtrun_rel_ends_at(const moqtrel_buf* rb, usz i, u64 at) {
  return at == rb->subs[i].end || (rb->fin_seen && at == rb->tail);
}

/* The publisher's FIN (or the End Object) reached cursor i with no bytes
 * pending: close its
 * stream via the byte-less stream_fin (the io contract forbids an empty
 * stream_send). A refusal retries next tick. */
void moqtrun_rel_try_fin(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i) {
  if (!moqtrun_rel_ends_at(rb, i, rb->subs[i].sent)) return;
  if (hub->io.stream_fin(wt, relay->sub_stream_id[i]) != 1) return;
  rb->subs[i].fin_done = 1;
  hub->stat_rel_fin_out++;
}

/* 1 when this round's last byte is the stream's last byte ever: the
 * send can carry the closing FIN itself. */
static int moqtrun_rel_round_fins(const moqtrel_buf* rb, usz i, usz n) {
  return moqtrun_rel_ends_at(rb, i, rb->subs[i].sent + n);
}

/* An accepted round: advance the cursor (restarting its stall clock) and
 * mark the FIN done when the round carried it. */
static void moqtrun_rel_round_ok(
    wired_moqt_hub* hub,
    moqtrel_buf*    rb,
    usz             i,
    usz             n,
    int             fin_flag,
    u64             now_ms) {
  moqtrel_note_sent(rb, (u32)i, n, now_ms);
  if (!fin_flag) return;
  rb->subs[i].fin_done = 1;
  hub->stat_rel_fin_out++;
}

/* 1 when session wt's remaining credit can carry an n-byte round and
 * still leave WIRED_MOQTREL_HEADROOM for the session's other (lossy)
 * traffic; a table without send_budget never constrains. */
static int moqtrun_rel_budget_ok(
    wired_moqt_hub* hub, wired_wt_session* wt, usz n) {
  if (!hub->io.send_budget) return 1;
  return hub->io.send_budget(wt) >= n + WIRED_MOQTREL_HEADROOM;
}

/* Budget gate for one round: 0 lets it proceed, 1 defers it whole,
 * counted on stat_rel_wait. The cursor AND its stall clock stay put: a
 * deferral is not progress, so a peer whose credit never recovers trips
 * moqtrel_stalled after WIRED_MOQTREL_STALL_MS and is shed exactly like
 * one whose sends are refused -- it must not pin the ring (and the
 * publisher hold) forever. A healthy line recovers credit within an RTT,
 * far under the stall clock. */
int moqtrun_rel_budget_wait(wired_moqt_hub* hub, wired_wt_session* wt, usz n) {
  if (moqtrun_rel_budget_ok(hub, wt, n)) return 0;
  hub->stat_rel_wait++;
  return 1;
}

/* moqtrel_next_round for cursor i, stopped at its End Object cut. */
wired_span moqtrun_rel_next(const moqtrel_buf* rb, usz i) {
  wired_span s   = moqtrel_next_round(rb, (u32)i);
  u64        end = rb->subs[i].end;
  if (end) s.n = (usz)u64_min(s.n, end - rb->subs[i].sent);
  return s;
}

/* The send itself: the FIN rides the stream's last byte; an accepted
 * round advances the cursor, a refusal changes nothing. */
void moqtrun_rel_send_span(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    wired_span           span,
    u64                  now_ms) {
  int fin_flag = moqtrun_rel_round_fins(rb, i, span.n);
  if (hub->io.stream_send(wt, relay->sub_stream_id[i], span, fin_flag) != 1) {
    hub->stat_rel_refused++;
    return;
  }
  hub->stat_rel_sent++;
  moqtrun_rel_round_ok(hub, rb, i, span.n, fin_flag, now_ms);
}
