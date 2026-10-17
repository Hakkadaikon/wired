#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_end_object_in_group(const wired_moqtrun_sub* s, u64 group);
static usz moqtrun_cutoff_scan(
    const wired_moqtrun_sub* s, wired_span wire, usz off0, moqdata_objseq seq0);
static usz moqtrun_startobj_scan(
    const wired_moqtrun_sub* s, wired_span wire, usz off, moqdata_objseq* seq);
static int  moqtrun_sub_in_objects(const wired_moqtrun_sub* s, moqctl_loc l);
static int  moqtrun_late_by(u64 timeout_ms, u64 age_ms);
static void moqtrun_sub_reresolve(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t);

/* 1 iff sub's End Object could fall somewhere inside Group group's wire
 * at all -- the moqtrun_wire_cutoff guard, split out to keep its own
 * branch count at the CCN gate. */
static int moqtrun_end_object_in_group(const wired_moqtrun_sub* s, u64 group) {
  return s->has_end_object && group == s->end_group;
}

/* moqtrun_wire_cutoff's decode walk, once its guard already confirmed s has
 * an End Object in this Group -- split out to keep moqtrun_wire_cutoff's
 * own branch count at the CCN gate. */
static usz moqtrun_cutoff_scan(
    const wired_moqtrun_sub* s,
    wired_span               wire,
    usz                      off0,
    moqdata_objseq           seq0) {
  usz         off = off0, cut = off0;
  moqdata_obj obj;
  while (moqdata_obj_take(wire, &off, &seq0, &obj) == MOQDATA_OK) {
    if (obj.object_id > s->end_object) return cut;
    cut = off;
  }
  return cut;
}

/* Byte offset in wire right after the last Object sub may still receive
 * this round: wire.n when sub has no End Object in Group g, or when none
 * of wire's Objects (decoded from off0/seq0, e.g. right after a
 * SUBGROUP_HEADER, or a header-less continuation's saved seq) crosses it.
 * draft-22 0x04's End Object is inclusive and Object-granular (SS3.3.1:
 * "a publisher MUST NOT send objects from outside the requested range"),
 * so a round carrying several Objects of the same Group is cut right
 * after the End Object, never re-framed past it. */
usz moqtrun_wire_cutoff(
    const wired_moqtrun_sub* s,
    wired_span               wire,
    usz                      off0,
    moqdata_objseq           seq0,
    u64                      group) {
  if (!moqtrun_end_object_in_group(s, group)) return wire.n;
  return moqtrun_cutoff_scan(s, wire, off0, seq0);
}

/* Offset of wire's first Object at or past s's start Object, decoding
 * from off with *seq (left at that Object): Objects of the start Group
 * below it are outside the Location Filter (d22 3.3.1: "a publisher MUST
 * NOT send objects from outside the requested range"). */
static usz moqtrun_startobj_scan(
    const wired_moqtrun_sub* s, wired_span wire, usz off, moqdata_objseq* seq) {
  usz            at = off;
  moqdata_objseq q  = *seq;
  moqdata_obj    obj;
  while (moqdata_obj_take(wire, &at, &q, &obj) == MOQDATA_OK &&
         obj.object_id < s->start.object) {
    off  = at;
    *seq = q;
  }
  return off;
}

/* moqtrun_startobj_scan for Objects of Group group; off itself outside
 * s's start Group. */
usz moqtrun_startobj_cut(
    const wired_moqtrun_sub* s,
    wired_span               wire,
    usz                      off,
    moqdata_objseq*          seq,
    u64                      group) {
  if (group != s->start.group) return off;
  return moqtrun_startobj_scan(s, wire, off, seq);
}

/* moqtrun_sub_gets for one Object at l (a datagram): also not before the
 * start Object nor past an End Object. */
static int moqtrun_sub_in_objects(const wired_moqtrun_sub* s, moqctl_loc l) {
  return !moqctl_loc_less(l, s->start) && !moqtrun_sub_past_end_object(s, l);
}

int moqtrun_sub_gets_loc(const wired_moqtrun_sub* s, moqctl_loc l) {
  return moqtrun_sub_gets(s, l.group) && moqtrun_sub_in_objects(s, l) &&
         moqtrun_sub_rngf_pass(s, l.object);
}

static int moqtrun_late_by(u64 timeout_ms, u64 age_ms) {
  return timeout_ms != 0 && age_ms > timeout_ms;
}

/* draft 8: an Object whose first byte reached the hub age_ms ago is past
 * s's OBJECT_DELIVERY_TIMEOUT or its effective SUBGROUP_DELIVERY_TIMEOUT
 * (0: none). */
int moqtrun_sub_late(const wired_moqtrun_sub* s, u64 age_ms) {
  return moqtrun_late_by(s->delivery_timeout, age_ms) ||
         moqtrun_late_by(s->subgroup_timeout, age_ms);
}

/* A re-attached subscription meets a new incarnation: a Largest-relative
 * filter start (9.3.1) and the Joining Location (5.1) are resolved again
 * against its Largest -- the stored ones name the old incarnation's
 * Objects. An absolute filter keeps the subscriber's own Locations. */
static void moqtrun_sub_reresolve(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t) {
  moqtrun_sub_resolve(s, t);
  s->jl     = t->largest;
  s->has_jl = (u8)t->has_largest;
}

/* Re-attaches peer i to track with the state it SUBSCRIBEd to k with
 * (Forward State, Request ID, parameters: only the subscriber changes
 * them, draft 5.1) under the alias its SUBSCRIBE_OK named -- the one its
 * client still holds (draft-22 3.1.3; moqtrun_session_alias kept it
 * reserved). */
void moqtrun_reattach_one_sub(
    wired_moqt_hub* hub, wired_moqtrun_track* track, usz i, moqtrun_key k) {
  const wired_moqtrun_peer* p = &hub->peers[i];
  usz                       n = moqtrun_sub_name_find(p, k);
  if (n >= WIRED_MOQTRUN_SUB_NAMES) return;
  wired_moqtrun_sub* slot = moqtrun_sub_slot(track);
  if (!slot) return;
  *slot             = p->sub_state[n];
  slot->session_idx = i;
  slot->active      = 1;
  moqtrun_sub_reresolve(slot, track);
  /* SSTS (moqtssts_run.c): the set dropped it while it had no track */
  moqtss_sub_leave(hub, slot);
  /* SWITCH_FROM (moqtswitch.c): bounds, a pending end swept again */
  moqtsw_reattached(hub, moqtrun_sw_ops(), slot);
}

/* A (re)PUBLISHed name re-attaches every still-connected peer that had
 * subscribed to it before -- silently, with no SUBSCRIBE_OK: the
 * subscriber's client still believes its original subscription stands
 * (that belief, standing while the hub-side subscription had died with
 * the publisher's previous incarnation, is exactly the played-into-
 * silence bug this repairs). The relayed bytes are re-spelled to the
 * alias the client already holds (moqtrun_alias_splice), so no
 * client-visible state needs renegotiating. */
void moqtrun_reattach_subs(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    usz                  pub_idx,
    moqtrun_key          k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (moqtrun_reattach_wanted(hub, track, i, pub_idx, k))
      moqtrun_reattach_one_sub(hub, track, i, k);
}

int moqtrun_encode_subscribe_ok(wired_mspan buf, usz* off, const void* m) {
  return moqctl_subscribe_ok_encode(buf, off, m);
}
