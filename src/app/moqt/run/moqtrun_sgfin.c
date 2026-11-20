#include "app/moqt/run/moqtrun_impl.h"
#include "common/bytes/text/text.h"

/* Malformed Track conditions tied to a Subgroup stream's FIN and its
 * Type bits (d22/d23 12.1 #2/#3/#6, d18/d19 2.4.2; END_OF_GROUP /
 * FIRST_OBJECT, 11.4.2 / 11.3.1) -- split out of moqtrun_decode.c to
 * keep that file at the Halstead volume gate. */

static int moqtrun_obj_rewound(const wired_moqtrun_track* t, moqctl_loc l);
static int moqtrun_obj_dup_lookup(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    moqctl_loc                 l,
    const moqdata_obj*         o);
static int moqtrun_obj_dup_differs(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    moqctl_loc                 l,
    const moqdata_obj*         o);
static int  moqtrun_sgf_same(const wired_moqtrun_track* t, u64 g, u64 sg);
static void moqtrun_sgf_past(wired_moqtrun_track* t, u64 g, u64 sg, u64 last);
static void moqtrun_sgf_fin(wired_moqtrun_track* t, u64 g, u64 sg, u64 last);
static void moqtrun_sgfin_record(
    wired_moqtrun_track* t, u64 type, u64 g, u64 sg, u64 last);
static int moqtrun_sgfin_skip(
    const wired_moqtrun_track* t, const moqdata_objseq* seq);
static void moqtrun_sgfin_note(
    wired_moqtrun_track*  t,
    u64                   type,
    u64                   g,
    u64                   sg,
    const moqdata_objseq* seq,
    int                   fin);

/* 1 iff l is at or behind t's Largest: only such an Object can be a
 * duplicate of one already received. */
static int moqtrun_obj_rewound(const wired_moqtrun_track* t, moqctl_loc l) {
  return t && t->has_largest && !moqctl_loc_less(t->largest, l);
}

/* The cache holds an Object exactly at l whose Payload differs from
 * o's. shortcut: moqcache_item_at scans from the cache's resume point
 * and moves it, so a burst of out-of-order Objects costs one partial
 * cache walk each; bound it with a per-track cursor if a publisher is
 * seen replaying long ranges. */
static int moqtrun_obj_dup_lookup(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    moqctl_loc                 l,
    const moqdata_obj*         o) {
  moqcache_item it;
  moqcache_item_at(&hub->cache, t->cache_tag, l, moqtrun_after(l), &it);
  return !it.unknown && it.loc.object == l.object &&
         !wired_span_eq(it.payload, o->payload);
}

/* d22 12.1 #6 (d18/19 2.4.2 #6): the same Object again with a different
 * Payload. Fresh ascending Objects skip the cache lookup. shortcut:
 * with no cache attached, or the first copy uncached (status-only, or
 * behind a later Group), nothing is detected -- and the datagram path
 * (moqtrun_dg.c) does not run this check at all; hook both up if a
 * publisher is seen mutating Objects. */
static int moqtrun_obj_dup_differs(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    moqctl_loc                 l,
    const moqdata_obj*         o) {
  if (!hub || !moqtrun_obj_rewound(t, l)) {
    return 0;
  }
  return moqtrun_obj_dup_lookup(hub, t, l, o);
}

/* The Object at l makes t Malformed on arrival: past a recorded end
 * (12.1 #4/#5), a Mandatory Track Property as an Object Property
 * (2.5.1), or a duplicate with a different Payload (12.1 #6). */
int moqtrun_obj_flags_malformed(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    moqctl_loc           l,
    const moqdata_obj*   o) {
  return moqtrun_obj_malformed(t, l) || moqtrun_obj_mand(t, o->props) ||
         moqtrun_obj_dup_differs(hub, t, l, o);
}

/* 1 iff the Subgroup whose final Object t knows (sgf_*) is {g, sg}. */
static int moqtrun_sgf_same(const wired_moqtrun_track* t, u64 g, u64 sg) {
  return t->sgf_set && t->sgf_group == g && t->sgf_id == sg;
}

/* 12.1 #2: an Object past the final Object of its FIN-terminated
 * Subgroup; last is the delivery's largest Object ID. */
static void moqtrun_sgf_past(wired_moqtrun_track* t, u64 g, u64 sg, u64 last) {
  if (moqtrun_sgf_same(t, g, sg) && last > t->sgf_final) {
    t->malformed = 1;
  }
}

/* 12.1 #3: a second FIN of the Subgroup with a different final Object;
 * otherwise the final is recorded. */
static void moqtrun_sgf_fin(wired_moqtrun_track* t, u64 g, u64 sg, u64 last) {
  if (moqtrun_sgf_same(t, g, sg)) {
    t->malformed |= last != t->sgf_final;
    return;
  }
  t->sgf_group = g;
  t->sgf_id    = sg;
  t->sgf_final = last;
  t->sgf_set   = 1;
}

/* A clean FIN of a Subgroup stream. A FIRST_OBJECT (0x40) stream carried
 * the Subgroup from its start (d22 2.2), so with d22 11.3's FIN rule
 * (FIN only after all Objects; anything less is a reset) its last Object
 * is the Subgroup's final (12.1 #2/#3). shortcut: 12.1 #2 reads the
 * final off EVERY FINed Subgroup stream, but senders in the wild (and
 * this repo's own fixtures) deliver one Subgroup as several FINed
 * one-Object streams, which the strict reading calls Malformed; the
 * FIRST_OBJECT gate trades that false positive for a miss on Subgroups
 * whose streams never carry the bit. Record from every clean FIN once
 * interop shows peers FIN strictly per Subgroup. The END_OF_GROUP bit
 * (0x08) fixes the Group's end at the same Object (11.4.2: no larger
 * Object ID exists in the Group). */
static void moqtrun_sgfin_record(
    wired_moqtrun_track* t, u64 type, u64 g, u64 sg, u64 last) {
  if (moqdata_type_first_object(type)) {
    moqtrun_sgf_fin(t, g, sg, last);
  }
  if (moqdata_type_end_of_group(type)) {
    moqtrun_track_note_end_on(
        t, moqctl_loc_of(g, last), MOQDATA_STATUS_END_OF_GROUP);
  }
}

/* 1 iff there is nothing to note: no track, or no Object decoded yet. */
static int moqtrun_sgfin_skip(
    const wired_moqtrun_track* t, const moqdata_objseq* seq) {
  return !t || !seq->have_prev;
}

/* Subgroup-stream state after a delivery of {g, sg} on t, decoded up to
 * seq: the #2 check against the recorded Subgroup final, and on a clean
 * FIN (fin; never on a reset) the record itself plus the Type-bit ends.
 * shortcut: the #2 check runs after the delivery's decode loop (the
 * Subgroup ID is per stream, not per Object), so the offending Object
 * was already counted and cached against 12.1's MUST NOT -- only until
 * the same wired_moqt_on_stream_data call's PUBLISH_DONE sweep retires
 * the track and moqtrun_track_retire drops its whole cache; check per
 * Object if a cached window ever survives longer. */
static void moqtrun_sgfin_note(
    wired_moqtrun_track*  t,
    u64                   type,
    u64                   g,
    u64                   sg,
    const moqdata_objseq* seq,
    int                   fin) {
  if (moqtrun_sgfin_skip(t, seq)) {
    return;
  }
  moqtrun_sgf_past(t, g, sg, seq->prev_id);
  if (fin) {
    moqtrun_sgfin_record(t, type, g, sg, seq->prev_id);
  }
}

/* 1 iff the stream ends here (fin) at an Object boundary. */
int moqtrun_fin_clean(int fin, usz off, usz n) { return fin && off == n; }

/* moqtrun_sgfin_note of a fresh stream's first delivery (its Subgroup ID
 * from the header; a mode-0b01 one from the first Object). */
void moqtrun_fresh_fin_note(
    wired_moqtrun_track*  t,
    wired_span            data,
    const moqdata_subhdr* hdr,
    const moqdata_objseq* seq,
    int                   fin) {
  u64 sg   = 0;
  u8  prio = 0;
  if (!moqtrun_sgprio_keys(t, data, &sg, &prio)) {
    return;
  }
  moqtrun_sgfin_note(t, hdr->type, hdr->group_id, sg, seq, fin);
}

/* The Type of relay's saved SUBGROUP_HEADER; 0 (no bits) when none was
 * saved (a torn head). moqtrun_relay_hdr_seq derives its decode state
 * from the same field. */
u64 moqtrun_relay_hdr_type(const wired_moqtrun_relay* r) {
  usz at = 0;
  u64 ty = 0;
  moqvi_take(wired_span_of(r->hdr, r->hdr_len), &at, &ty);
  return ty;
}

/* moqtrun_sgfin_note of a kept-open relayed stream after a delivery
 * (relay->seq is past it); the FIN is clean only with no torn tail held.
 * No note from a relay without a saved header (hdr_len 0: a torn
 * mode-0b01 head left its Subgroup ID unknown, moqtrun_relay_save_hdr)
 * or a poisoned one (an Object was dropped mid-stream, so the last
 * Object received is not relay->seq's). */
void moqtrun_relay_fin_note(
    wired_moqtrun_track* t, const wired_moqtrun_relay* r, int fin) {
  if (!r->hdr_len || moqtrun_relay_poisoned(r)) {
    return;
  }
  /* (off, n) repurposed as (frag_len, 0): clean iff no torn tail held. */
  moqtrun_sgfin_note(
      t, moqtrun_relay_hdr_type(r), r->group_id, r->subgroup_id, &r->seq,
      moqtrun_fin_clean(fin, r->frag_len, 0));
}
