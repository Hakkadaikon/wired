#include "app/moqt/run/moqtrun_impl.h"

static int  moqtrun_is_bare_fin(wired_span wire, int fin);
static void moqtrun_relay_shed_one(
    wired_moqt_hub*          hub,
    wired_wt_session*        wt,
    const wired_moqtrun_sub* sub,
    wired_moqtrun_relay*     relay,
    usz                      i);
static void moqtrun_relay_note_busy(
    wired_moqt_hub*          hub,
    wired_wt_session*        wt,
    const wired_moqtrun_sub* sub,
    wired_moqtrun_relay*     relay,
    usz                      i);

/* Finds the relay entry (across p's tracks) already following
 * pub_stream_id, filling *track_out with its owning track. 0 when this
 * stream id is not being relayed (a fresh stream, or one whose relay was
 * dropped). */
wired_moqtrun_relay* moqtrun_peer_relay_by_stream(
    wired_moqtrun_peer* p, u64 pub_stream_id, wired_moqtrun_track** track_out) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++) {
    wired_moqtrun_relay* r =
        moqtrun_track_relay_or_null(&p->tracks[t], pub_stream_id);
    if (r) {
      *track_out = &p->tracks[t];
      return r;
    }
  }
  return 0;
}

wired_moqtrun_relay* moqtrun_relay_alloc(wired_moqtrun_track* track) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++)
    if (!track->relays[r].in_use) return &track->relays[r];
  return 0;
}

/* True when this round carries the publisher's own stream FIN with no new
 * Object bytes of its own -- a WebTransport writer's close() can arrive as
 * its own byte-less call, separate from the data written just before it
 * (confirmed against a real browser: a chat message's data and its FIN
 * landed as two distinct wired_moqt_on_stream_data calls). stream_send
 * cannot carry this (srvrun.h: a round's payload must be non-empty), so
 * the caller routes it to stream_fin instead. */
static int moqtrun_is_bare_fin(wired_span wire, int fin) {
  return wire.n == 0 && fin;
}

/* Sub slot i's busy streak has reached the shed threshold: abandon its
 * relay stream (io.stream_reset -- error code 0, MOQT draft-19 defines no
 * standard code for a mid-subgroup abort) so the NEXT round re-opens a
 * fresh stream at the newest frame via moqtrun_relay_late_open, using the
 * relay's saved SUBGROUP_HEADER. A switching-set member (video) is not
 * re-opened: its Objects past the cut cannot decode without the Group's
 * start, so the rest of the Subgroup is skipped (sub_expired). A refused
 * reset (the SDK's reset latch is full this step) keeps everything as-is:
 * the saturated streak retries the shed on the next busy round. */
static void moqtrun_relay_shed_one(
    wired_moqt_hub*          hub,
    wired_wt_session*        wt,
    const wired_moqtrun_sub* sub,
    wired_moqtrun_relay*     relay,
    usz                      i) {
  if (relay->sub_busy_streak[i] < WIRED_MOQTRUN_RESET_AFTER_BUSY) return;
  if (hub->io.stream_reset(wt, relay->sub_stream_id[i], 0) != 1) return;
  relay->sub_stream_set[i]  = 0;
  relay->sub_busy_streak[i] = 0;
  relay->sub_expired |= (u32)(moqtss_sub_in_set(sub) != 0) << i;
  hub->stat_relay_reset++;
  moqtss_note_shed(hub, wt); /* SSTS (moqtssts_run.c): congestion */
}

/* One refused relay round for sub slot i: count the drop, advance the busy
 * streak (saturating -- 255 stays 255 so a long starvation cannot wrap back
 * under the threshold), and shed the stream once the streak says the
 * fullness is sustained, not a transient burst. */
static void moqtrun_relay_note_busy(
    wired_moqt_hub*          hub,
    wired_wt_session*        wt,
    const wired_moqtrun_sub* sub,
    wired_moqtrun_relay*     relay,
    usz                      i) {
  hub->stat_relay_drop++;
  if (relay->sub_busy_streak[i] < 255) relay->sub_busy_streak[i]++;
  moqtrun_relay_shed_one(hub, wt, sub, relay, i);
}

/* wire for sub slot i: as is, unless i's stream was late-opened and has
 * not been sent an Object yet (sub_reframe) -- then its first Object's
 * Object ID Delta (chained from seq0 on the publisher's stream) becomes
 * the absolute Object ID, as the first Object of the subscriber's stream
 * is read (draft-22 11.3.1), built in hub->alias_scratch. */
wired_span moqtrun_relay_reframe(
    wired_moqt_hub*            hub,
    const wired_moqtrun_relay* relay,
    usz                        i,
    wired_span                 wire,
    moqdata_objseq             seq0) {
  if (!(relay->sub_reframe >> i & 1)) return wire;
  usz n = moqtrun_reframe_to(hub->alias_scratch, wire, seq0);
  return n ? wired_span_of(hub->alias_scratch, n) : wire;
}

/* Forwards one round of publisher bytes to sub slot i's already-open relay
 * stream: a bare FIN closes it via stream_fin (moqtrun_is_bare_fin's doc),
 * anything else appends via stream_send with fin passed through (its first
 * Object re-framed after a late open, moqtrun_relay_reframe). A
 * stream_send rejection (previous round not yet ACKed -- srvrun.h) drops
 * this one round for this subscriber, counted on the hub: voice is
 * loss-tolerant, and chat's rounds are paced far apart enough that in
 * practice only voice hits it. Sustained rejection sheds the stream
 * entirely (moqtrun_relay_note_busy) -- delivering the newest frame beats
 * faithfully replaying a stale backlog. */
void moqtrun_relay_forward_one(
    wired_moqt_hub*          hub,
    wired_wt_session*        wt,
    const wired_moqtrun_sub* sub,
    wired_moqtrun_relay*     relay,
    usz                      i,
    moqtrun_round            r) {
  if (moqtrun_is_bare_fin(r.wire, r.fin)) {
    hub->io.stream_fin(wt, relay->sub_stream_id[i]);
    return;
  }
  wired_span wire = moqtrun_relay_reframe(hub, relay, i, r.wire, r.seq0);
  if (hub->io.stream_send(wt, relay->sub_stream_id[i], wire, r.fin) == 1) {
    hub->stat_relay_sent++;
    relay->sub_busy_streak[i] = 0;
    relay->sub_reframe &= ~((u32)1 << i);
    return;
  }
  moqtrun_relay_note_busy(hub, wt, sub, relay, i);
}
