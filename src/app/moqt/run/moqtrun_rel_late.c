#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_rel_late_attach(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u64                  now_ms);

/* A late subscriber on a ring that still holds the whole stream: its
 * stream replays the ring from its first Object at or past the start
 * Object (moqtrun_startobj_cut; Objects before it are covered by a
 * Joining Fetch, 10.12.2.1), ended at its End Object. With no such
 * Object yet nothing opens, and the next drain looks again; an open
 * failure attaches nothing and retries on the next drain too.
 * ponytail: a ring reclaimed past its header meanwhile is not replayed
 * (moqtrun_rel_holds_start); attach a waiting cursor if that loses
 * Objects a late subscriber needs. */
void moqtrun_rel_replay(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u64                  now_ms) {
  wired_moqtrun_sub* sub = &track->subs[i];
  wired_span         body =
      wired_span_of(rb->buf + relay->hdr_len, (usz)(rb->tail - relay->hdr_len));
  moqdata_objseq s0  = moqtrun_relay_hdr_seq(relay);
  moqdata_objseq seq = s0;
  usz off = moqtrun_startobj_cut(sub, body, 0, &seq, relay->group_id);
  if (off == body.n) {
    return;
  }
  moqtrun_rel_replay_open(hub, sub, relay, i, off);
  moqtrun_rel_attach_sub(rb, track, relay, i, relay->hdr_len + off, now_ms);
  moqtrun_rel_replay_cuts(relay, &rb->subs[i], sub, i, body, off, seq);
}

static void moqtrun_rel_late_attach(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u64                  now_ms) {
  if (!moqtrun_rel_late_wanted(track, relay, rb, i) ||
      !moqtrun_rel_replay_ok(&track->subs[i], relay, rb)) {
    return;
  }
  moqtrun_rel_replay(hub, track, relay, rb, i, now_ms);
}

/* Covers both ways a subscription turns active mid-stream (SUBSCRIBE, and
 * the silent re-attach): every drain looks for such slots. */
void moqtrun_rel_late_attach_all(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    u64                  now_ms) {
  if (!moqtrun_rel_holds_start(relay, rb)) {
    return;
  }
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    moqtrun_rel_late_attach(hub, track, relay, rb, i, now_ms);
  }
}

/* 1 while cursor i still expects delivery work (live, not given up on,
 * not yet FIN'd) -- the && chain lives here for the CCN gate. */
int moqtrun_rel_sub_open(const moqtrel_buf* rb, usz i) {
  return rb->subs[i].active && !rb->subs[i].shed && !rb->subs[i].fin_done;
}

/* Destination peer for cursor i's sends, or 0 when the cursor has no
 * work (indexing peers[] on an inactive slot would read a garbage
 * session_idx -- same guard as every other session_idx use here) or the
 * peer vanished (skipped, retried next tick). */
wired_moqtrun_peer* moqtrun_rel_sub_dst(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* track,
    const moqtrel_buf*         rb,
    usz                        i) {
  if (!moqtrun_rel_sub_open(rb, i)) {
    return 0;
  }
  wired_moqtrun_peer* dst = &hub->peers[track->subs[i].session_idx];
  return dst->in_use ? dst : 0;
}

/* Gives up on stalled sub slot i: reset its relay stream and mark the
 * cursor shed so it stops pinning the ring. Unlike the lossy shed, a
 * reliable shed never re-opens, so a refused reset is not retried -- it
 * only costs that peer a dangling stream. The relay's record of the
 * stream clears too (as the lossy shed does): should this entry later
 * fall back to the lossy continue, a round must never stream_send to the
 * reset stream -- the subscriber late-opens afresh instead. */
void moqtrun_rel_shed(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u32                  code) {
  hub->io.stream_reset(wt, relay->sub_stream_id[i], code);
  relay->sub_stream_set[i] = 0;
  rb->subs[i].shed         = 1;
  hub->stat_rel_stall += code == 0;
  moqtss_note_shed(hub, wt); /* SSTS (moqtssts_run.c): congestion */
  if (code == MOQTRUN_RESET_DELIVERY_TIMEOUT) {
    moqtrun_note_expired(hub, relay, i);
  }
}
