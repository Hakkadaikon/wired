#include "app/moqt/run/moqtrun_impl.h"

static u8  moqtrun_pub_prio(wired_span head, u8 dflt);
static int moqtrun_alias_spot(wired_span wire, usz* at, usz* end, u64* cur);

/* SUBSCRIBE for the live track: a held subscription is re-answered
 * (moqtrun_sub_held_reply, nothing re-sent), anyone else is attached
 * and served the current Group. */
void moqtrun_subscribe_live(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m) {
  wired_moqtrun_track* t    = &hub->live.track;
  wired_moqtrun_sub*   held = moqtrun_track_sub_of_peer(t, peer_idx);
  if (moqtrun_sub_held_reply(p, t, held)) {
    return;
  }
  wired_moqtrun_sub* slot = moqtrun_sub_slot(t);
  if (!slot) {
    moqtrun_send_request_error(p, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  moqtrun_live_attach(hub, p, slot, peer_idx, m);
}

/* ===================== data-stream (Object) relay ===================== */

/* The Publisher Priority of the SUBGROUP_HEADER head starts with: dflt
 * (the track's DEFAULT_PUBLISHER_PRIORITY, 12.4) when the DEFAULT_PRIORITY
 * bit omits it, or head does not decode. */
static u8 moqtrun_pub_prio(wired_span head, u8 dflt) {
  usz            off = 0;
  moqdata_subhdr h;
  if (moqdata_subhdr_take(head, &off, &h) != MOQDATA_OK) {
    return dflt;
  }
  return moqdata_type_default_priority(h.type) ? dflt : (u8)h.priority;
}

/* Sets the class (moqtrun_sub_key) of subscriber stream sid just opened
 * for sub, head being its opening SUBGROUP_HEADER; one that does not
 * decode ranks as Group 0, Subgroup 0. */
void moqtrun_prio_set(
    wired_moqt_hub*          hub,
    wired_wt_session*        wt,
    i64                      sid,
    const wired_moqtrun_sub* sub,
    wired_span               head,
    u8                       dflt) {
  usz            off = 0;
  moqdata_subhdr h   = {0};
  (void)moqdata_subhdr_take(head, &off, &h);
  wired_wt_sched k = moqtrun_sub_key(
      sub, moqtrun_pub_prio(head, dflt), h.group_id, h.subgroup_id);
  moqtrun_sched_apply(hub, wt, sid, &k);
}

/* One-shot relay of wire to one subscriber: a fresh uni stream, sent and
 * FIN'd in a single io.send_uni call -- the whole-message-in-one-call path
 * (a publisher stream whose data AND fin arrived together). */
void moqtrun_relay_to_one(
    wired_moqt_hub* hub, wired_moqtrun_sub* sub, wired_span wire, u8 dflt) {
  wired_moqtrun_peer* dst = &hub->peers[sub->session_idx];
  if (!dst->in_use) {
    return;
  }
  /* A refused one-shot open loses this subscriber's whole message (chat's
   * 1 stream = 1 message); count it like the keep-open path's open
   * failures -- stat_open_drop's own doc always promised this loss is
   * never silent, but this call site used to discard the return. */
  i64 sid = hub->io.send_uni(dst->wt, wire);
  hub->stat_open_drop += sid < 0;
  sub->stream_count += sid >= 0;
  moqtrun_prio_set(hub, dst->wt, sid, sub, wire, dflt);
}

/* wire cut to sub's End Object (moqtrun_wire_cutoff), re-reading wire's own
 * SUBGROUP_HEADER for the Object decode's starting point and seq -- wire
 * always starts with one here (moqtrun_relay_object's caller only reaches
 * this for a fresh stream). A header that fails to decode is passed whole;
 * moqtrun_subgroup_scan already did (and acted on) the real decode. */
wired_span moqtrun_hdr_cutoff(
    const wired_moqtrun_sub* s, wired_span wire, u64 group) {
  usz            off = 0;
  moqdata_subhdr hdr;
  if (moqdata_subhdr_take(wire, &off, &hdr) != MOQDATA_OK) {
    return wire;
  }
  moqdata_objseq seq = moqdata_objseq_of(hdr.type);
  usz            cut = moqtrun_wire_cutoff(s, wire, off, seq, group);
  return wired_span_of(wire.p, cut);
}

/* Offsets of wire's Track Alias -- the vi64 right after the Type in a
 * SUBGROUP_HEADER (draft-22 11.3.1) and an OBJECT_DATAGRAM (11.2.1)
 * alike -- and its value; 0 when either does not decode. */
static int moqtrun_alias_spot(wired_span wire, usz* at, usz* end, u64* cur) {
  usz off = 0;
  u64 type;
  if (!moqvi_take(wire, &off, &type)) {
    return 0;
  }
  *at = off;
  if (!moqvi_take(wire, &off, cur)) {
    return 0;
  }
  *end = off;
  return 1;
}

/* 1 iff wire names another alias than a and a re-spelled copy fits
 * hub->alias_scratch. */
int moqtrun_alias_respell(
    const wired_moqt_hub* hub, wired_span wire, u64 a, usz* at, usz* end) {
  u64 cur = a;
  return moqtrun_alias_spot(wire, at, end, &cur) && cur != a &&
         wire.n + 8 <= sizeof hub->alias_scratch;
}
