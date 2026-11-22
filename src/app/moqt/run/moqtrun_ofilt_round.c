#include "app/moqt/run/moqtrun_impl.h"

/* The round side of per-Object Range Filters (moqtrun_ofilt.c): a
 * subscriber cut per Object gets each round's passing Objects
 * re-chained onto the last Object its stream was actually sent (a
 * refused round leaves the chain where it was), its stream opened only
 * once a round has an Object for it. */

static int moqtrun_ofilt_joins(
    const wired_moqtrun_relay* relay, usz i, const wired_moqtrun_sub* sub);
static int moqtrun_ofilt_on(
    wired_moqtrun_relay*     relay,
    usz                      i,
    const wired_moqtrun_sub* sub,
    moqdata_objseq           seq0);
static void moqtrun_ofilt_late_open(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i);
static int moqtrun_ofilt_ready(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    moqtrun_round        r);
static int moqtrun_relay_cut_rider(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_relay* relay,
    usz                        i);

/* sub's Range Filters started cutting Objects mid-stream (REQUEST_UPDATE)
 * and slot i is at an Object boundary (no part of one sent ahead). */
static int moqtrun_ofilt_joins(
    const wired_moqtrun_relay* relay, usz i, const wired_moqtrun_sub* sub) {
  return moqtrun_sub_cuts_objects(sub) && relay->sub_part[i] == 0;
}

/* 1 when slot i's rounds are cut per Object: since its stream opened
 * (moqtrun_ofilt_opened), or from now on -- its chain then continuing
 * the publisher's as sent so far (seq0; none while its first Object
 * awaits re-framing). A slot stays cut for the rest of the stream. */
static int moqtrun_ofilt_on(
    wired_moqtrun_relay*     relay,
    usz                      i,
    const wired_moqtrun_sub* sub,
    moqdata_objseq           seq0) {
  u32 bit = moqtrun_sub_bit(i);
  if (relay->sub_cut & bit) {
    return 1;
  }
  if (!moqtrun_ofilt_joins(relay, i, sub)) {
    return 0;
  }
  int have =
      seq0.have_prev & relay->sub_stream_set[i] & !(relay->sub_reframe & bit);
  relay->sub_cut |= bit;
  relay->sub_dhave    = (relay->sub_dhave & ~bit) | ((u32)(have != 0) << i);
  relay->sub_dprev[i] = seq0.prev_id;
  relay->sub_reframe &= ~bit; /* the cut round's first Object is absolute */
  return 1;
}

/* Opens slot i's stream head-only: the saved head as a late joiner's
 * (moqtrun_relay_late_hdr), END_OF_GROUP cleared (moqtrun_ofilt.c). */
static void moqtrun_ofilt_late_open(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i) {
  u8 hdr[WIRED_MOQTRUN_RELAY_HDR_MAX];
  if (!relay->hdr_len) {
    return;
  }
  usz n = moqtrun_relay_late_hdr(relay, hdr);
  hdr[0] &= (u8)~0x08U; /* the Type is one byte (draft-22 11.3.1) */
  moqtrun_relay_open_one(hub, sub, relay, i, wired_span_of(hdr, n));
}

/* Slot i's stream is open for r: already, or opened now that r has an
 * Object for it. */
static int moqtrun_ofilt_ready(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    moqtrun_round        r) {
  if (relay->sub_stream_set[i]) {
    return 1;
  }
  if (!moqtrun_ofilt_keeps(sub, relay, i, r)) {
    return 0;
  }
  moqtrun_ofilt_late_open(hub, sub, relay, i);
  return relay->sub_stream_set[i];
}

/* moqtrun_relay_deliver_one, slot i's round cut per Object when its
 * Range Filters cut Objects (the re-chained round in alias_scratch is
 * built after a late open, whose alias splice uses it too). */
void moqtrun_ofilt_deliver(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_peer*  dst,
    wired_moqtrun_relay* relay,
    usz                  i,
    moqtrun_round        r) {
  if (!moqtrun_ofilt_on(relay, i, sub, r.seq0)) {
    moqtrun_relay_deliver_one(hub, sub, dst, relay, i, r);
    return;
  }
  if (moqtrun_ofilt_ready(hub, sub, relay, i, r)) {
    moqtrun_relay_deliver_one(
        hub, sub, dst, relay, i, moqtrun_ofilt_round(hub, sub, relay, i, r));
  }
}

/* Slot i, served by relay and cut per Object, has no ring cursor
 * (moqtrun_sub_rides_ring kept it off the ring). */
static int moqtrun_relay_cut_rider(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_relay* relay,
    usz                        i) {
  return moqtrun_sub_gets_relay(s, relay) &&
         moqtrun_ofilt_cutting(relay, i, s) &&
         !moqtrun_rel_sub_open(&hub->rel_pool[relay->rel_idx], i);
}

/* A ring-backed relay's round to its subscribers cut per Object: lossy,
 * per round (moqtrun_relay_append_one), beside the ring's cursors.
 * shortcut: a ring cursor whose Range Filter gains an Object filter
 * mid-stream keeps riding the ring unfiltered until the stream ends. */
void moqtrun_relay_append_cut(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           wire,
    moqdata_objseq       seq0,
    int                  fin,
    u64                  born_ms) {
  moqtrun_round r = {wire, seq0, fin};
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    if (moqtrun_relay_cut_rider(hub, &track->subs[i], relay, i)) {
      moqtrun_relay_append_one(hub, &track->subs[i], relay, i, r, born_ms);
    }
  }
}

/* A refused round on slot i, cut per Object beside a reliable relay's
 * ring: its unfiltered siblings lose nothing, so a silent hole would read
 * as filtering. The stream is reset instead (d22 11.3.2: the subscriber
 * learns it is incomplete) and reopened at a later kept Object
 * (moqtrun_ofilt_ready); a refused reset stops the slot for the
 * Subgroup, as moqtrun_cut_refused does. 1 when it applied. */
int moqtrun_ofilt_refused(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    usz                  i) {
  if (!moqtrun_ofilt_ring_cut(relay, i)) {
    return 0;
  }
  if (hub->io.stream_reset(
          wt, relay->sub_stream_id[i], MOQTRUN_RESET_INTERNAL_ERROR) != 1) {
    relay->sub_expired |= moqtrun_sub_bit(i);
  }
  relay->sub_stream_set[i] = 0;
  hub->stat_relay_reset++;
  return 1;
}
