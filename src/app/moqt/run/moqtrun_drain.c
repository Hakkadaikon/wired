#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_track_done_peer(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz idx, u64 status);
static int moqtrun_subs_held(const wired_moqtrun_track* t, usz idx);
static int moqtrun_track_held(const wired_moqtrun_track* t, usz idx);
static int moqtrun_peer_tracks_held(const wired_moqtrun_peer* q, usz idx);
static int moqtrun_peer_held(const wired_moqtrun_peer* q, usz idx);
static int moqtrun_own_held(const wired_moqt_hub* hub, usz idx);
static int moqtrun_hub_held(const wired_moqt_hub* hub, usz idx);
static int moqtrun_peer_publishes(const wired_moqtrun_peer* p);
static int moqtrun_peer_quiet(wired_moqt_hub* hub, wired_moqtrun_peer* p);
static u32 moqtrun_drain_close_code(wired_moqt_hub* hub, wired_moqtrun_peer* p);
static int moqtrun_drain_closeable(const wired_moqtrun_peer* p, u64 now_ms);
static void moqtrun_ctl_step(wired_moqt_hub* hub, wired_moqtrun_peer* p);

/* PUBLISH_DONE status to each subscription peer index idx holds on t. */
static void moqtrun_track_done_peer(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz idx, u64 status) {
  for (usz si = 0; si < WIRED_MOQTRUN_MAX_SUBS; si++)
    if (moqtrun_sub_is_peer(&t->subs[si], idx))
      moqtrun_sub_done_slot(hub, t, si, status);
}

/* Subscription slots of t held by peer index idx. */
static int moqtrun_subs_held(const wired_moqtrun_track* t, usz idx) {
  for (usz si = 0; si < WIRED_MOQTRUN_MAX_SUBS; si++)
    if (moqtrun_sub_is_peer(&t->subs[si], idx)) return 1;
  return 0;
}

static int moqtrun_track_held(const wired_moqtrun_track* t, usz idx) {
  return t->in_use && moqtrun_subs_held(t, idx);
}

static int moqtrun_peer_tracks_held(const wired_moqtrun_peer* q, usz idx) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    if (moqtrun_track_held(&q->tracks[t], idx)) return 1;
  return 0;
}

static int moqtrun_peer_held(const wired_moqtrun_peer* q, usz idx) {
  return q->in_use && moqtrun_peer_tracks_held(q, idx);
}

static int moqtrun_own_held(const wired_moqt_hub* hub, usz idx) {
  return moqtrun_track_held(&hub->blob_track, idx) ||
         moqtrun_track_held(&hub->live.track, idx);
}

/* Peer index idx still holds a subscription on any track. */
static int moqtrun_hub_held(const wired_moqt_hub* hub, usz idx) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (moqtrun_peer_held(&hub->peers[i], idx)) return 1;
  return moqtrun_own_held(hub, idx);
}

static int moqtrun_peer_publishes(const wired_moqtrun_peer* p) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    if (p->tracks[t].in_use) return 1;
  return 0;
}

/* Nothing of p's is open any more: no request stream, no track it
 * publishes, no subscription it holds. */
static int moqtrun_peer_quiet(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  return moqtrun_req_count(hub, p->wt) == 0 && !moqtrun_peer_publishes(p) &&
         !moqtrun_hub_held(hub, (usz)(p - hub->peers));
}

/* draft-ietf-moq-transport-19 10.4: GOAWAY_TIMEOUT only while requests
 * are still open, NO_ERROR (3.5) once nothing is left. */
static u32 moqtrun_drain_close_code(
    wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  return moqtrun_peer_quiet(hub, p) ? WIRED_MOQTRUN_CLOSE_NO_ERROR
                                    : WIRED_MOQTRUN_CLOSE_GOAWAY_TIMEOUT;
}

/* p flushed PUBLISH_DONE and is past the real-time grace that follows:
 * only then may the close happen, so a loaded peer gets WIRED_MOQTRUN_
 * GOAWAY_GRACE_MS of wall-clock time -- not merely the next tick,
 * whenever that lands -- to read the flush before the session is gone. */
static int moqtrun_drain_closeable(const wired_moqtrun_peer* p, u64 now_ms) {
  return p->goaway_flushed_at &&
         now_ms > p->goaway_flushed_at + WIRED_MOQTRUN_GOAWAY_GRACE_MS;
}

/* The flush step of moqtrun_drain_expire: PUBLISH_DONE GOING_AWAY to
 * every subscription p holds, its queued answers sent (the tick's
 * moqtrun_reqs_tick then FINs those streams), and the flush's own
 * timestamp marked for moqtrun_drain_closeable to time the close from. */
void moqtrun_drain_flush(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 now_ms) {
  moqtrun_each_track(
      hub, moqtrun_track_done_peer, (usz)(p - hub->peers),
      MOQCTL_DONE_GOING_AWAY);
  moqtrun_rp_flush(hub, p);
  moqtrun_flush_replies(&hub->io, p);
  p->goaway_flushed_at = now_ms ? now_ms : 1; /* 0 means "not yet" */
}

/* Past the GOAWAY Timeout (3.6): moqtrun_drain_flush once, then close
 * only once moqtrun_drain_closeable allows it (moqtrun_drain_close_code)
 * -- never on the very next tick, so a loaded peer gets real wall-clock
 * time to read the flush before the session is gone. */
void moqtrun_drain_expire(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 now_ms) {
  if (!p->goaway_flushed_at) {
    moqtrun_drain_flush(hub, p, now_ms);
    return;
  }
  if (moqtrun_drain_closeable(p, now_ms))
    moqtrun_peer_close(hub, p, moqtrun_drain_close_code(hub, p));
}

int moqtrun_drain_due(const wired_moqtrun_peer* p, u64 now_ms) {
  return p->in_use && !p->closing && now_ms >= p->goaway_deadline;
}

/* A control stream whose open was refused is re-opened; after that,
 * replies refused earlier (moqtrun_flush_replies) are retried. */
static void moqtrun_ctl_step(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  if (!p->ctl_opened) {
    moqtrun_ctl_open(hub, p);
    return;
  }
  moqtrun_flush_replies(&hub->io, p);
}

/* Control-stream opens and replies refused earlier are retried on the
 * clock too, not only when the peer sends again: SETUP and GOAWAY must
 * go out even to a silent peer. */
void moqtrun_ctl_retry(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  if (p->in_use && !p->closing) moqtrun_ctl_step(hub, p);
}
