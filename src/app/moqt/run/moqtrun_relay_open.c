#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_relay_supersedes(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_sub*   sub,
    const wired_moqtrun_relay* relay);
static void moqtrun_sub_note_open(
    wired_moqt_hub*            hub,
    wired_wt_session*          wt,
    wired_moqtrun_sub*         sub,
    const wired_moqtrun_relay* relay,
    u64                        sid);
static void moqtrun_relay_opened(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  dst,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    i64                  sid,
    wired_span           out);
static int moqtrun_relay_dst_ok(
    wired_moqt_hub*            hub,
    const wired_moqtrun_peer*  dst,
    const wired_moqtrun_sub*   sub,
    const wired_moqtrun_relay* relay);
static void moqtrun_relay_open_sub(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    wired_span           wire);

/* relay's newer Group supersedes sub's older ones (hub policy). */
static int moqtrun_relay_supersedes(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_sub*   sub,
    const wired_moqtrun_relay* relay) {
  return hub->newest_group_only && moqtrun_relay_newer_for(sub, relay);
}

/* Lossy stream sid just opened for sub on relay, under
 * hub->newest_group_only: in a newer Group it resets the previous newest
 * stream -- even one the publisher already FIN'd and the hub stopped
 * tracking -- so its stale backlog does not hold the newer Group back
 * (draft-22 7.2 sends a subscription's Groups in order), and becomes the
 * newest. Off, newest_sid stays 0, so moqtrun_relay_stale_for never cuts
 * an older Group either. */
static void moqtrun_sub_note_open(
    wired_moqt_hub*            hub,
    wired_wt_session*          wt,
    wired_moqtrun_sub*         sub,
    const wired_moqtrun_relay* relay,
    u64                        sid) {
  if (!moqtrun_relay_supersedes(hub, sub, relay)) {
    return;
  }
  if (sub->newest_sid) {
    hub->io.stream_reset(wt, sub->newest_sid, MOQTRUN_RESET_INTERNAL_ERROR);
  }
  sub->newest_group = relay->group_id;
  sub->newest_sid   = sid;
}

/* Opens sub slot i's relay stream carrying wire, cut to sub's End Object
 * (moqtrun_hdr_cutoff) when wire still starts with its SUBGROUP_HEADER --
 * a late-open's wire is header-only (relay->hdr_len, no Objects) and the
 * cutoff passes it through unchanged. A cut that dropped bytes FINs the
 * stream right away (moqtrun_relay_open_end_hit): no further round will
 * ever reach it. Records the id for later rounds. An open failure (no
 * free send slot on that connection) leaves the slot unset: a lossy relay
 * late-opens it on a later round (moqtrun_relay_late_open), a ring-backed
 * one retries on the next drain while the ring still holds the stream's
 * start (moqtrun_rel_late_attach_all), else it gets nothing. */
/* Records sub slot i's freshly opened relay stream sid (sent out first). */
static void moqtrun_relay_opened(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  dst,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    i64                  sid,
    wired_span           out) {
  moqtrun_prio_set(hub, dst->wt, sid, sub, out, relay->default_pub_prio);
  sub->stream_count++;
  moqtrun_sub_note_open(hub, dst->wt, sub, relay, (u64)sid);
  relay->sub_stream_id[i]   = (u64)sid;
  relay->sub_stream_set[i]  = 1;
  relay->sub_busy_streak[i] = 0;
  relay->sub_part[i]        = 0;
}

/* dst is connected and sub not fed relay's Subgroup by a sibling mirror
 * (moqtrun_dd_dup). */
static int moqtrun_relay_dst_ok(
    wired_moqt_hub*            hub,
    const wired_moqtrun_peer*  dst,
    const wired_moqtrun_sub*   sub,
    const wired_moqtrun_relay* relay) {
  return dst->in_use &&
         !moqtrun_dd_dup(hub, sub, 0, relay->group_id, relay->subgroup_id);
}

void moqtrun_relay_open_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    wired_span           wire) {
  wired_moqtrun_peer* dst = &hub->peers[sub->session_idx];
  if (!moqtrun_relay_dst_ok(hub, dst, sub, relay)) {
    return;
  }
  wired_span cut_wire = moqtrun_hdr_cutoff(sub, wire, relay->group_id);
  wired_span out      = moqtrun_alias_splice(hub, cut_wire, sub->track_alias);
  i64        sid      = hub->io.open_uni_stream(dst->wt, out);
  if (sid < 0) {
    hub->stat_open_drop++;
    return;
  }
  moqtrun_relay_opened(hub, dst, sub, relay, i, sid, out);
  moqtrun_relay_open_end_hit(
      hub, dst->wt, (u64)sid, relay, i, cut_wire.n, wire.n);
}

/* The opening round to sub slot i, cut to its start Object
 * (moqtrun_head_startobj_cut): a cut that left no Object opens the stream
 * head-only, its first Object re-framed later (sub_reframe). */
static void moqtrun_relay_open_sub(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    wired_span           wire) {
  int        bare;
  wired_span w = moqtrun_head_startobj_cut(
      hub, sub, wire, relay->group_id, relay->subgroup_id, &bare);
  moqtrun_relay_open_one(hub, sub, relay, i, w);
  relay->sub_reframe |= (u32)(bare & relay->sub_stream_set[i]) << i;
}

void moqtrun_relay_open_all(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           wire) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    if (moqtrun_sub_gets_relay(&track->subs[i], relay)) {
      moqtrun_relay_open_sub(hub, &track->subs[i], relay, i, wire);
    }
  }
}

/* Saves the stream's SUBGROUP_HEADER bytes on relay for late-joining
 * subscribers (moqtrun_relay_late_open). data starts with the header --
 * this is only called for a stream that already classified and decoded as
 * SUBGROUP, so a decode failure here cannot really happen; it just leaves
 * hdr_len 0 (late joiners are then skipped rather than sent garbage). */
void moqtrun_relay_save_hdr_raw(
    wired_moqtrun_relay* relay, wired_span data, usz off) {
  if (off > WIRED_MOQTRUN_RELAY_HDR_MAX) {
    return;
  }
  bytes_memcpy(relay->hdr, data.p, off);
  relay->hdr_len = off;
}
