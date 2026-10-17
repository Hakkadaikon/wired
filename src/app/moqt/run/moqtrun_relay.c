#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_relay_object_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_sub*   s,
    wired_span           wire,
    u64                  group,
    u64                  sg);
static int moqtrun_relay_matches(
    const wired_moqtrun_relay* r, u64 pub_stream_id);
static wired_moqtrun_relay* moqtrun_track_relay_by_stream(
    wired_moqtrun_track* track, u64 pub_stream_id);

/* h as the head of a stream that starts past its Subgroup's first Object:
 * FIRST_OBJECT (0x40) cleared (draft-22 2.2 / 11.3.1), and a mode-0b01
 * Subgroup ID, which names the publisher stream's first Object, spelled
 * out as sg (mode 0b10). Written to out; its length. */
usz moqtrun_late_hdr_of(moqdata_subhdr h, u64 sg, u8* out) {
  usz n = 0;
  h.type &= ~0x40ULL;
  if (moqdata_type_sgid_mode(h.type) == 1) {
    h.type        = (h.type & ~0x06ULL) | 0x04ULL;
    h.subgroup_id = sg;
  }
  moqdata_subhdr_put(wired_mspan_of(out, WIRED_MOQTRUN_RELAY_HDR_MAX), &n, &h);
  return n;
}

/* wire (a SUBGROUP_HEADER, then Objects of Group group, Subgroup sg) as
 * s may receive it: wire itself when no Object precedes s's start Object
 * (moqtrun_startobj_cut), else re-framed in hub->relay_scratch -- a late
 * head (moqtrun_late_hdr_of) and the rest, its first Object absolute
 * (moqtrun_reframe_to). *bare is 1 when the cut left no Object. */
wired_span moqtrun_head_startobj_cut(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* s,
    wired_span               wire,
    u64                      group,
    u64                      sg,
    int*                     bare) {
  usz            off = 0;
  moqdata_subhdr h;
  *bare = 0;
  if (moqdata_subhdr_take(wire, &off, &h) != MOQDATA_OK) {
    return wire;
  }
  moqdata_objseq seq = moqdata_objseq_of(h.type);
  usz            cut = moqtrun_startobj_cut(s, wire, off, &seq, group);
  if (cut == off) {
    return wire;
  }
  *bare = cut == wire.n;
  usz n = moqtrun_late_hdr_of(h, sg, hub->relay_scratch);
  n += moqtrun_reframe_to(
      hub->relay_scratch + n, wired_span_of(wire.p + cut, wire.n - cut), seq);
  return wired_span_of(hub->relay_scratch, n);
}

/* One-shot relay of a whole stream to s, cut to its Location Filter's
 * start and End Objects; nothing at all when no Object is left. */
static void moqtrun_relay_object_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_sub*   s,
    wired_span           wire,
    u64                  group,
    u64                  sg) {
  int        bare;
  wired_span w = moqtrun_head_startobj_cut(hub, s, wire, group, sg, &bare);
  if (bare) {
    return;
  }
  moqtrun_relay_to_one(
      hub, s,
      moqtrun_alias_splice(
          hub, moqtrun_hdr_cutoff(s, w, group), s->track_alias),
      track->default_pub_prio);
}

void moqtrun_relay_object(
    wired_moqt_hub* hub, wired_moqtrun_track* track, wired_span wire) {
  moqdata_objseq seq;
  u64            group = 0, sg = 0;
  u8             prio = track->default_pub_prio;
  moqtrun_subgroup_scan(wire, 0, &seq, &group);
  moqtrun_stream_keys(wire, track->default_pub_prio, &sg, &prio);
  moqtss_prime(hub, track, group); /* SSTS (moqtssts_run.c) */
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    if (moqtrun_sub_gets_stream(&track->subs[i], group, sg, prio)) {
      moqtrun_relay_object_one(hub, track, &track->subs[i], wire, group, sg);
    }
  }
}

static int moqtrun_relay_matches(
    const wired_moqtrun_relay* r, u64 pub_stream_id) {
  return r->in_use && r->pub_stream_id == pub_stream_id;
}

static wired_moqtrun_relay* moqtrun_track_relay_by_stream(
    wired_moqtrun_track* track, u64 pub_stream_id) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++) {
    if (moqtrun_relay_matches(&track->relays[r], pub_stream_id)) {
      return &track->relays[r];
    }
  }
  return 0;
}

wired_moqtrun_relay* moqtrun_track_relay_or_null(
    wired_moqtrun_track* track, u64 pub_stream_id) {
  return track->in_use ? moqtrun_track_relay_by_stream(track, pub_stream_id)
                       : 0;
}
