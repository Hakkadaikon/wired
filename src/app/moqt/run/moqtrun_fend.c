#include "app/moqt/run/moqtrun_impl.h"

/* draft-23 3.2.2: "The publisher MUST follow an Object known to end the
 * Track with End of Track, and MUST follow the last Object in the
 * response with End of Group if it is known to end its Group." What the
 * hub knows: the End of Group / End of Track status Objects it received
 * (moqtrun_track_note_end_on). A Group closed by a later one is no such
 * record (2.1.2: a gap conveys nothing; 12.1 item 4). */

static int moqtrun_fend_none(
    wired_moqt_hub* hub, u64 tag, moqctl_loc from, moqctl_loc to);
static int moqtrun_fend_eog_at(const wired_moqtrun_track* t, u64 g);
static int moqtrun_fend_group_end(
    const wired_moqtrun_track* t, moqctl_loc l, moqctl_loc* end);
static int moqtrun_fend_track_ends(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l);
static int moqtrun_fend_group_ends(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l);
static u64 moqtrun_fend_flags(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l);
static int moqtrun_fend_is_obj(wired_moqt_hub* hub, u64 tag, moqctl_loc l);
static int moqtrun_fend_held(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l);
static u64 moqtrun_fend_of(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f, moqctl_loc l);
static int moqtrun_fend_due(const moqfetch_seq* s, int fin);
static int moqtrun_upf_mark_out(const wired_moqtrun_fetch* f);
static int moqtrun_fend_gaps_unknown(const wired_moqtrun_fetch* f);
static int moqtrun_fend_eot_past(const wired_moqtrun_track* t, moqctl_loc l);
static int moqtrun_fend_eog_past(const wired_moqtrun_track* t, moqctl_loc l);
static moqctl_loc moqtrun_fend_known(
    const wired_moqtrun_track* t, moqctl_loc from);
static int moqtrun_upf_mark_send(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, const moqfetch_obj* o);

/* The cache holds no Object in [from, to). */
static int moqtrun_fend_none(
    wired_moqt_hub* hub, u64 tag, moqctl_loc from, moqctl_loc to) {
  return !moqctl_loc_less(moqcache_skip(&hub->cache, tag, from, to), to);
}

static int moqtrun_fend_eog_at(const wired_moqtrun_track* t, u64 g) {
  return (t->end_flags & 2) && t->group_end.group == g;
}

/* 1 with *end where l's Group is known to end: its End of Group status. */
static int moqtrun_fend_group_end(
    const wired_moqtrun_track* t, moqctl_loc l, moqctl_loc* end) {
  *end = t->group_end;
  return moqtrun_fend_eog_at(t, l.group);
}

static int moqtrun_fend_track_ends(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l) {
  return (t->end_flags & 1) &&
         moqtrun_fend_none(hub, t->cache_tag, moqtrun_after(l), t->track_end);
}

static int moqtrun_fend_group_ends(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l) {
  moqctl_loc end;
  return moqtrun_fend_group_end(t, l, &end) &&
         moqtrun_fend_none(hub, t->cache_tag, moqtrun_after(l), end);
}

/* End of Track also indicates End of Group (11.4.2.2); 0 for none. */
static u64 moqtrun_fend_flags(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l) {
  if (moqtrun_fend_track_ends(hub, t, l)) {
    return MOQFETCH_END_OF_TRACK;
  }
  return moqtrun_fend_group_ends(hub, t, l) ? MOQFETCH_END_OF_GROUP : 0;
}

/* l is a cached Object, not the end of an unknown range. */
static int moqtrun_fend_is_obj(wired_moqt_hub* hub, u64 tag, moqctl_loc l) {
  moqcache_item it;
  moqcache_item_at(&hub->cache, tag, l, moqtrun_after(l), &it);
  return !it.unknown;
}

static int moqtrun_fend_held(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l) {
  return t && moqtrun_fend_is_obj(hub, t->cache_tag, l);
}

/* The marker following f's last item, the Object at l; 0 for none. */
static u64 moqtrun_fend_of(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f, moqctl_loc l) {
  const wired_moqtrun_track* t = moqtrun_upf_track(hub, f);
  return moqtrun_fend_held(hub, t, l) ? moqtrun_fend_flags(hub, t, l) : 0;
}

static int moqtrun_fend_due(const moqfetch_seq* s, int fin) {
  return fin && s->d23;
}

/* n bytes of f's last item staged in relay_scratch, then the marker that
 * follows it on a draft-23 stream when fin; the new length (seq advanced
 * past the marker). */
usz moqtrun_fend_mark(
    wired_moqt_hub*            hub,
    const wired_moqtrun_fetch* f,
    moqfetch_seq*              seq,
    usz                        n,
    int                        fin) {
  moqfetch_obj o = {0};
  if (moqtrun_fend_due(seq, fin)) {
    o.flags = moqtrun_fend_of(hub, f, moqctl_loc_of(seq->group, seq->object));
  }
  if (o.flags) {
    moqfetch_obj_put(
        wired_mspan_of(hub->relay_scratch, sizeof hub->relay_scratch), &n, seq,
        &o);
  }
  return n;
}

/* ----- gaps a draft-23 stream leaves unmarked ----- */

/* draft-23 3.2.2: without Range Filters an unmarked gap says the Objects
 * do not exist. */
static int moqtrun_fend_gaps_unknown(const wired_moqtrun_fetch* f) {
  return f->seq.d23 && !f->rngf_n;
}

static int moqtrun_fend_eot_past(const wired_moqtrun_track* t, moqctl_loc l) {
  return (t->end_flags & 1) && !moqctl_loc_less(l, t->track_end);
}

static int moqtrun_fend_eog_past(const wired_moqtrun_track* t, moqctl_loc l) {
  return moqtrun_fend_eog_at(t, l.group) && !moqctl_loc_less(l, t->group_end);
}

/* How far from the hub knows nothing exists: past an End of Track to
 * anywhere, past an End of Group to the next Group, else nowhere. */
static moqctl_loc moqtrun_fend_known(
    const wired_moqtrun_track* t, moqctl_loc from) {
  if (moqtrun_fend_eot_past(t, from)) {
    return moqctl_loc_of(~0ULL, ~0ULL);
  }
  return moqtrun_fend_eog_past(t, from) ? moqctl_loc_of(from.group + 1, 0)
                                        : from;
}

/* cur, where the cache's skip from from landed, cut back on a draft-23
 * stream to what the hub knows does not exist (2.1.2: "MUST NOT signal
 * that an Object does not exist unless it knows"); the cursor stops
 * there and the cache reports the rest as an unknown range. */
moqctl_loc moqtrun_fend_skip(
    wired_moqt_hub*            hub,
    const wired_moqtrun_fetch* f,
    moqctl_loc                 from,
    moqctl_loc                 cur) {
  const wired_moqtrun_track* t = moqtrun_upf_track(hub, f);
  if (!moqtrun_fend_gaps_unknown(f) || !t) {
    return cur;
  }
  return moqctl_loc_min(cur, moqtrun_fend_known(t, from));
}

/* ----- relaying an upstream End of Group / Track ----- */

/* The item before went out on a stream whose draft has End of Group /
 * Track (draft-23 11.4.1). */
static int moqtrun_upf_mark_out(const wired_moqtrun_fetch* f) {
  return f->seq.d23 && f->has_up_last && !f->up_skip;
}

static int moqtrun_upf_mark_send(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, const moqfetch_obj* o) {
  moqfetch_seq seq = f->seq;
  usz          n   = 0;
  if (!moqfetch_obj_put(
          wired_mspan_of(hub->relay_scratch, sizeof hub->relay_scratch), &n,
          &seq, o) ||
      !moqtrun_upf_send_item(hub, f, n)) {
    return 0;
  }
  f->seq        = seq;
  f->last_ok_ms = hub->live.last_now_ms;
  return 1;
}

/* draft-23 11.4.2.2: End of Group / Track ends the item before it, so it
 * goes on right after that item (the leg's place stays there), and is
 * left out where that item was not relayed or the draft lacks it. */
int moqtrun_upf_end_mark(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, const moqfetch_obj* o) {
  if (!moqtrun_upf_mark_out(f)) {
    return 1;
  }
  return moqtrun_upf_mark_send(hub, f, o);
}
