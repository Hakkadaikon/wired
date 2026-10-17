#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_live_has_empty_frag(const wired_span* frags, usz n_frags);
static int moqtrun_live_args_bad(
    const wired_span* frags, usz n_frags, u64 group_ms);
static int moqtrun_live_head_obj(wired_mspan buf, usz* off, usz frag_len);

/* ===================== hub-owned live track ===================== */

/* 1 iff any fragment is empty: an empty Object payload requires an
 * explicit Status varint after Payload Length 0 (moqdata_obj_put's doc),
 * which the live head (Delta + Length only) never carries -- such a
 * fragment could not frame as a valid Object, so the publish is refused
 * whole. */
static int moqtrun_live_has_empty_frag(const wired_span* frags, usz n_frags) {
  for (usz f = 0; f < n_frags; f++)
    if (frags[f].n == 0) return 1;
  return 0;
}

static int moqtrun_live_args_bad(
    const wired_span* frags, usz n_frags, u64 group_ms) {
  if (n_frags == 0 || group_ms == 0) return 1;
  return moqtrun_live_has_empty_frag(frags, n_frags);
}

int wired_moqt_publish_live(
    wired_moqt_hub*   hub,
    wired_span        name,
    u64               track_alias,
    const wired_span* frags,
    usz               n_frags,
    u64               group_ms,
    u64               now_ms) {
  if (moqtrun_live_args_bad(frags, n_frags, group_ms) ||
      moqtrun_key_oversized(moqtrun_key_name(name)))
    return 0;
  /* a re-publish forgets old subscribers; the old incarnation's cache and
   * fills go first, as on any track's end */
  moqtrun_track_cache_drop(hub, &hub->live.track);
  hub->live.track.in_use = 0;
  moqtrun_track_claim(
      hub, &hub->live.track, moqtrun_key_name(name), track_alias);
  hub->live.frags       = frags;
  hub->live.n_frags     = n_frags;
  hub->live.t0_ms       = now_ms;
  hub->live.group_ms    = group_ms;
  hub->live.last_now_ms = now_ms;
  moqtrun_track_note(&hub->live.track, 0, 0); /* Group 0 starts at t0 */
  return 1;
}

u64 moqtrun_live_group_at(const wired_moqtrun_live* live, u64 now_ms) {
  return now_ms < live->t0_ms ? 0 : (now_ms - live->t0_ms) / live->group_ms;
}

/* The Object's ID Delta 0 and Payload Length -- exactly the varints
 * moqdata_obj_put emits ahead of a non-empty payload, so head||fragment
 * is byte-identical to what moqdata_obj_put would have written. */
static int moqtrun_live_head_obj(wired_mspan buf, usz* off, usz frag_len) {
  if (!moqvi_put(buf, off, 0)) return 0;
  return moqvi_put(buf, off, frag_len);
}

/* SUBGROUP_HEADER (Type 0x70 shape, live alias, Group g) + the Object's
 * ID Delta 0 and Payload Length -- the framing that precedes the fragment
 * bytes on the wire. Returns the head length (<= MOQDATA_MSG_OVERHEAD). */
usz moqtrun_live_head(
    const wired_moqtrun_live* live, u64 group, usz frag_len, u8* head) {
  usz            off = 0;
  moqdata_subhdr h   = {0};
  h.type             = MOQDATA_MSG_TYPE;
  h.track_alias      = live->track.own_alias;
  h.group_id         = group;
  wired_mspan buf    = wired_mspan_of(head, MOQDATA_MSG_OVERHEAD);
  if (moqdata_subhdr_put(buf, &off, &h) != MOQDATA_OK) return 0;
  if (!moqtrun_live_head_obj(buf, &off, frag_len)) return 0;
  return off;
}

/* 1 iff sub slot i still owes Group g (never sent, or last sent older). */
int moqtrun_live_owes(const wired_moqtrun_live* live, usz i, u64 g) {
  return !live->sent_any[i] || live->sent_group[i] < g;
}

/* Groups the clock skipped past sub slot i's last accepted send (0 when
 * none): each is a fragment this subscriber was never sent -- never sent
 * late once its Group has passed, only counted. */
u64 moqtrun_live_gap(const wired_moqtrun_live* live, usz i, u64 g) {
  return live->sent_any[i] && live->sent_group[i] + 1 < g
             ? g - live->sent_group[i] - 1
             : 0;
}

/* 1 iff Group g may open for sub slot i: its peer is connected, g passes
 * the Location Filter (5.1.4), and g's Object -- produced when g began --
 * is not past the OBJECT_DELIVERY_TIMEOUT (draft 8: no stream is opened
 * for it). */
int moqtrun_live_due(
    const wired_moqt_hub* hub, const wired_moqtrun_peer* dst, usz i, u64 g) {
  const wired_moqtrun_live* live = &hub->live;
  const wired_moqtrun_sub*  s    = &live->track.subs[i];
  u64                       born = live->t0_ms + g * live->group_ms;
  return dst->in_use && moqtrun_sub_wants_group(s, g) &&
         !moqtrun_sub_late(s, live->last_now_ms - born);
}
