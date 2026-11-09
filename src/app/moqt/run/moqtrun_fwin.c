#include "app/moqt/run/moqtrun_impl.h"

static int  moqtrun_fetch_timed_out(const wired_moqtrun_fetch* f);
static u64  moqtrun_fetch_eor(const wired_moqtrun_fetch* f);
static void moqtrun_fwin_down(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f, moqtrun_fwin* w);
static int moqtrun_fwin_more(
    const wired_moqtrun_fetch* f, const moqtrun_fwin* w);

int moqtrun_fetch_new_group(const moqfetch_seq* s, u64 group) {
  return !s->have_loc || s->group != group;
}

/* s encodes a fetch stream of draft ver's session: 0x20C from draft-22
 * SS11.4.1, the draft-23 11.4 encoding. */
void moqtrun_fseq_ver(moqfetch_seq* s, int ver) {
  u64 caps         = moqver_caps(ver);
  s->eor_timed_out = (caps & MOQVER_CAP_EOR_TIMED_OUT) != 0;
  s->d23           = (caps & MOQVER_CAP_FETCH_STREAM23) != 0;
}

/* A miss the upstream budget ran out on (or FILL_TIMEOUT 0 forbade
 * asking for) is End of Timed-Out Range, on a fill as on a FETCH
 * (draft-23 3.2.3, 3.4, 9.19.5); anything else -- a miss the hub only
 * infers -- and every miss toward a draft without 0x20C, is End of
 * Unknown Range (3.2.2). */
static int moqtrun_fetch_timed_out(const wired_moqtrun_fetch* f) {
  return f->up_tmo && f->seq.eor_timed_out;
}

static u64 moqtrun_fetch_eor(const wired_moqtrun_fetch* f) {
  return moqtrun_fetch_timed_out(f) ? MOQFETCH_EOR_TIMED_OUT
                                    : MOQFETCH_EOR_UNKNOWN;
}

/* A cache item as a fetch Object (11.4.4.1): Object ID Delta (except
 * where draft-23 11.4.1.1 needs it left out) and Publisher Priority
 * always present (the cache keeps no priority, so the
 * 12.4 default 128), Group ID Delta when the group changes, Subgroup ID
 * zero. An unknown range is an End of Range marker, eor (11.4.4.2). */
void moqtrun_fetch_obj_of(
    moqfetch_obj* o, const moqcache_item* it, const moqfetch_seq* s, u64 eor) {
  bytes_memset(o, 0, sizeof *o);
  o->group  = it->loc.group;
  o->object = it->loc.object;
  o->flags  = eor;
  if (it->unknown) {
    return;
  }
  o->flags = moqfetch_object_flag(s, it->loc.group, it->loc.object) |
             MOQFETCH_F_PRIORITY |
             (moqtrun_fetch_new_group(s, it->loc.group) ? MOQFETCH_F_GROUP : 0);
  o->has_subgroup = 1;
  o->priority     = 128;
  o->payload      = it->payload;
}

int moqtrun_fwin_drained(const moqtrun_fwin* w) {
  return !moqctl_loc_less(w->cursor, w->end);
}

/* The Group a window's exclusive end lies in. */
u64 moqtrun_fwin_group(const moqtrun_fwin* w) {
  return w->end.object ? w->end.group : w->end.group - 1;
}

/* w moved one group down (11.4.4.1 Descending), clipped to f's lo. */
static void moqtrun_fwin_down(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f, moqtrun_fwin* w) {
  u64        g    = moqtrun_fwin_group(w) - 1;
  moqctl_loc from = g == f->lo.group ? f->lo : moqctl_loc_of(g, 0);
  w->end          = moqctl_loc_of(g + 1, 0);
  w->cursor       = moqtrun_fsel_fskip(hub, f, from, w->end);
}

/* 1 while a drained descending window still has lower groups to serve. */
static int moqtrun_fwin_more(
    const wired_moqtrun_fetch* f, const moqtrun_fwin* w) {
  return f->descending && moqtrun_fwin_drained(w) &&
         moqtrun_fwin_group(w) != f->lo.group;
}

/* f's serving state once the item ending at from is out: the cursor
 * skipped within the window, a descending fill stepped down past any
 * group with nothing to serve. Drained = the fetch is over (FIN). */
void moqtrun_fetch_after(
    wired_moqt_hub*            hub,
    const wired_moqtrun_fetch* f,
    moqctl_loc                 from,
    moqtrun_fwin*              w) {
  w->end    = f->end;
  w->cursor = moqtrun_fsel_fskip(hub, f, from, w->end);
  while (moqtrun_fwin_more(f, w)) {
    moqtrun_fwin_down(hub, f, w);
  }
}

/* Sends the item at f's cursor (FIN on the last); 0 when the transport
 * refused it -- the cursor stays and the item is looked up afresh on the
 * next try. relay_scratch is free here (its doc). */
/* Encodes the item at f's cursor into relay_scratch; returns its length,
 * seq advanced past it and *next the location after it. */
usz moqtrun_fetch_encode_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_fetch* f,
    moqfetch_seq*        seq,
    moqctl_loc*          next) {
  moqcache_item it;
  moqfetch_obj  o;
  usz           n = 0;
  moqcache_item_at(&hub->cache, f->cache_tag, f->cursor, f->end, &it);
  moqtrun_fetch_obj_of(
      &o, &it, seq,
      it.gone ? moqtrun_upf_eor_of(MOQFETCH_EOR_GONE, seq)
              : moqtrun_fetch_eor(f));
  moqfetch_obj_put(
      wired_mspan_of(hub->relay_scratch, sizeof hub->relay_scratch), &n, seq,
      &o);
  *next = it.next;
  return n;
}

/* f past the item just sent: its seq, window and liveness stamp. */
void moqtrun_fetch_advance(
    wired_moqt_hub*      hub,
    wired_moqtrun_fetch* f,
    moqfetch_seq         seq,
    const moqtrun_fwin*  w) {
  f->seq        = seq;
  f->cursor     = w->cursor;
  f->end        = w->end;
  f->last_ok_ms = hub->live.last_now_ms;
}
