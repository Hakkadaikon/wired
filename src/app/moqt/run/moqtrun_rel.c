#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_track_is_reliable(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t);
static moqtrel_buf* moqtrun_rel_acquire(wired_moqt_hub* hub);
static void         moqtrun_rel_bind(
    wired_moqt_hub*      hub,
    wired_moqtrun_relay* relay,
    wired_wt_session*    pub_wt,
    u64                  pub_stream_id,
    wired_span           head);

/* 1 if this normalized round carries anything worth forwarding: whole
 * Objects, or the publisher's FIN (which must reach the subscriber streams
 * even with no bytes of its own). */
int moqtrun_relay_round_due(wired_span whole, int fin) {
  return whole.n != 0 || fin;
}

/* ========== reliable relay: ring-backed forwarding (moqtrel) ==========
 * A track whose own_alias is below hub->reliable_alias_limit forwards
 * through a moqtrel ring instead of the drop-on-refusal path above:
 * refused sends retry from the ring on later ticks, and the publisher's
 * receive credit is held (io.stream_hold) when the ring nears capacity --
 * bytes are delayed, never dropped, for every subscriber that keeps up.
 * The ring module only decides (moqtrel.h); every io call stays here. */

static int moqtrun_track_is_reliable(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  return t->own_alias < hub->reliable_alias_limit;
}

/* First free ring in the pool, or 0 (the caller falls back to lossy). */
static moqtrel_buf* moqtrun_rel_acquire(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTREL_POOL; i++)
    if (!hub->rel_pool[i].in_use) return &hub->rel_pool[i];
  return 0;
}

/* Ring append, counting the by-design-impossible refusal: the hold
 * watermark keeps free space ahead of the publisher's window, so a full
 * ring is an invariant violation to record (stat_rel_overflow, the
 * reliable twin of stat_frag_drop), not a loss to handle. born_ms is the
 * round's oldest unflushed byte's arrival (moqtrun_relay_normalize's twin
 * for the lossy path, draft 8's "reached the hub" moment), not necessarily
 * now: a torn Object waits in the relay's fragment first. */
void moqtrun_rel_take(
    wired_moqt_hub* hub, moqtrel_buf* rb, wired_span whole, u64 born_ms) {
  if (whole.n == 0) return;
  if (!moqtrel_append(rb, whole)) {
    hub->stat_rel_overflow++;
    return;
  }
  moqtrel_mark(rb, born_ms);
  hub->stat_rel_in_bytes += whole.n;
}

/* Binds a free ring to relay for a reliable track: the publisher recorded
 * for the hold/release calls, the opening round (header + whole Objects)
 * appended so cursor offsets match the true stream offsets. An exhausted
 * pool counts stat_relay_full and leaves rel_idx -1: the caller's lossy
 * start continues unchanged (the fallback path). */
static void moqtrun_rel_bind(
    wired_moqt_hub*      hub,
    wired_moqtrun_relay* relay,
    wired_wt_session*    pub_wt,
    u64                  pub_stream_id,
    wired_span           head) {
  moqtrel_buf* rb = moqtrun_rel_acquire(hub);
  if (!rb) {
    hub->stat_relay_full++; /* pool dry: this stream relays lossily */
    return;
  }
  moqtrel_reset(rb);
  rb->in_use     = 1;
  rb->pub        = pub_wt;
  rb->pub_stream = pub_stream_id;
  rb->bound_ms   = hub->live.last_now_ms;
  moqtrun_rel_take(hub, rb, head, hub->live.last_now_ms);
  relay->rel_idx = (i32)(rb - hub->rel_pool);
  hub->stat_rel_rings++;
}

/* Reliable gate for a fresh keep-open stream: only a track below the
 * alias limit, and only when the io table can actually hold the
 * publisher back (without stream_hold a ring would only overflow). */
void moqtrun_rel_start(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_wt_session*    pub_wt,
    u64                  pub_stream_id,
    wired_span           head) {
  if (!hub->io.stream_hold || !moqtrun_track_is_reliable(hub, track)) return;
  moqtrun_rel_bind(hub, relay, pub_wt, pub_stream_id, head);
}

/* Activates sub slot i's ring cursor at offset sent if its relay stream
 * opened (the stream already carries every byte before sent); the stall
 * clock anchors at now_ms. head moves up to sent: no cursor reads below
 * it, and a nonzero head ends moqtrel_awaits_sub's wait. */
void moqtrun_rel_attach_sub(
    moqtrel_buf*               rb,
    const wired_moqtrun_track* track,
    const wired_moqtrun_relay* relay,
    usz                        i,
    u64                        sent,
    u64                        now_ms) {
  if (!moqtrun_sub_forwards(&track->subs[i]) || !relay->sub_stream_set[i])
    return;
  rb->subs[i].active       = 1;
  rb->subs[i].shed         = 0; /* a reused slot must not inherit these */
  rb->subs[i].fin_done     = 0;
  rb->subs[i].sent         = sent;
  rb->subs[i].last_ok_ms   = now_ms;
  rb->subs[i].end          = 0;
  rb->subs[i].lead_skip    = 0;
  rb->subs[i].before_start = 0;
  rb->head                 = sent;
}

/* Sub slot i's opening stream as a ring cursor at tail -- unless the open
 * already ended it at its End Object (sub_expired). A head-only open cut
 * before its start Object (sub_reframe) waits for that Object. */
void moqtrun_rel_attach_open(
    moqtrel_buf*               rb,
    const wired_moqtrun_track* track,
    const wired_moqtrun_relay* relay,
    usz                        i,
    u64                        now_ms) {
  if (relay->sub_expired >> i & 1) return;
  moqtrun_rel_attach_sub(rb, track, relay, i, rb->tail, now_ms);
  rb->subs[i].before_start = (int)(relay->sub_reframe >> i & 1);
}
