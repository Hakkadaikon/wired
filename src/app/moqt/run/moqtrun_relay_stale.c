#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_relay_stale_cut(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* sub,
    wired_moqtrun_peer*      dst,
    wired_moqtrun_relay*     relay,
    usz                      i);
static int moqtrun_relay_gone(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* sub,
    wired_moqtrun_peer*      dst,
    wired_moqtrun_relay*     relay,
    usz                      i,
    u64                      born_ms);
static wired_span moqtrun_relay_end_cut(
    wired_moqtrun_relay*     relay,
    usz                      i,
    wired_span               wire,
    moqdata_objseq           seq0,
    const wired_moqtrun_sub* sub,
    int*                     fin);
static void moqtrun_relay_append_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    moqtrun_round        r,
    u64                  born_ms);

/* relay is a lossy stream of a Group older than the newest sub was
 * opened a stream in (wired_moqtrun_sub.newest_sid). */
int moqtrun_relay_stale_for(
    const wired_moqtrun_sub* sub, const wired_moqtrun_relay* relay) {
  return relay->rel_idx < 0 && sub->newest_sid &&
         relay->group_id < sub->newest_group;
}

/* A newer Group superseded relay for sub slot i: its stream is reset (a
 * second reset of the newest_sid one is a no-op) and i skipped for the
 * rest of the Subgroup -- no append, no late re-open. 1 when it was. */
static int moqtrun_relay_stale_cut(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* sub,
    wired_moqtrun_peer*      dst,
    wired_moqtrun_relay*     relay,
    usz                      i) {
  if (!moqtrun_relay_stale_for(sub, relay)) return 0;
  if (relay->sub_stream_set[i])
    hub->io.stream_reset(
        dst->wt, relay->sub_stream_id[i], MOQTRUN_RESET_INTERNAL_ERROR);
  relay->sub_stream_set[i] = 0;
  relay->sub_expired |= moqtrun_sub_bit(i);
  return 1;
}

/* Sub slot i no longer takes relay's rounds: superseded by a newer
 * Group, or past its delivery timeout. */
static int moqtrun_relay_gone(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* sub,
    wired_moqtrun_peer*      dst,
    wired_moqtrun_relay*     relay,
    usz                      i,
    u64                      born_ms) {
  return moqtrun_relay_stale_cut(hub, sub, dst, relay, i) ||
         moqtrun_relay_expire(hub, sub, dst, relay, i, born_ms);
}

/* wire cut to sub's End Object for relay's sub slot i (moqtrun_wire_
 * cutoff, decoding from seq0 -- the chaining state right before this
 * round). A cut that drops any bytes marks i expired on relay (10.9.1: no
 * further round reaches a subscriber past its End Object) so later
 * rounds skip it via moqtrun_relay_skips, and forces fin: this IS sub's
 * last delivery, whole.n or not. */
static wired_span moqtrun_relay_end_cut(
    wired_moqtrun_relay*     relay,
    usz                      i,
    wired_span               wire,
    moqdata_objseq           seq0,
    const wired_moqtrun_sub* sub,
    int*                     fin) {
  usz cut = moqtrun_wire_cutoff(sub, wire, 0, seq0, relay->group_id);
  if (cut == wire.n) return wire;
  relay->sub_expired |= moqtrun_sub_bit(i);
  *fin = 1;
  return wired_span_of(wire.p, cut);
}

/* One subscriber's share of a relayed round whose oldest Object arrived
 * at born_ms, cut to sub's start Object (moqtrun_startobj_cut, a cut
 * round starts at the stream's first Object sent: it follows a head-only
 * open, so moqtrun_relay_reframe makes it absolute) and End Object
 * (moqtrun_relay_end_cut) when wire's Objects cross them. */
static void moqtrun_relay_append_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    moqtrun_round        r,
    u64                  born_ms) {
  wired_moqtrun_peer* dst = &hub->peers[sub->session_idx];
  if (moqtrun_relay_skips(dst, relay, i)) return;
  if (moqtrun_relay_gone(hub, sub, dst, relay, i, born_ms)) return;
  usz cut = moqtrun_startobj_cut(sub, r.wire, 0, &r.seq0, relay->group_id);
  r.wire  = wired_span_of(r.wire.p + cut, r.wire.n - cut);
  r.wire  = moqtrun_relay_end_cut(relay, i, r.wire, r.seq0, sub, &r.fin);
  moqtrun_relay_deliver_one(hub, sub, dst, relay, i, r);
}

void moqtrun_relay_append_all(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           wire,
    moqdata_objseq       seq0,
    int                  fin,
    u64                  born_ms) {
  moqtrun_round r = {wire, seq0, fin};
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (moqtrun_sub_gets_relay(&track->subs[i], relay))
      moqtrun_relay_append_one(hub, &track->subs[i], relay, i, r, born_ms);
}
