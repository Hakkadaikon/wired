#include "app/moqt/dgram/moqdg_impl.h" /* moqdg_type_default_prio */
#include "app/moqt/run/moqtrun_impl.h"

/* Which subscriptions are cut per Object (moqtrun_ofilt.c), the
 * datagram twin of its per-Object gate, and the downstream chain each
 * cut stream continues from. */

static int moqtrun_ofilt_row_cuts(const wired_moqtrun_rngrow* r);
static int moqtrun_ofilt_stays(
    const wired_moqtrun_relay* relay, usz i, const wired_moqtrun_sub* sub);

static int moqtrun_ofilt_row_cuts(const wired_moqtrun_rngrow* r) {
  return r->ptype == MOQCTL_PARAM_OBJECTID_FILTER ||
         r->ptype == MOQCTL_PARAM_OBJECT_PROPERTY_FILTER;
}

/* opening a stream to s waits: none of its opening Objects passed s's
 * per-Object Range Filters (bare). */
int moqtrun_ofilt_waits(const wired_moqtrun_sub* s, int bare) {
  return bare && moqtrun_sub_cuts_objects(s);
}

/* The datagram o as a Range Filter sees it: its Object ID, Publisher
 * Priority (dflt under DEFAULT_PRIORITY, draft-22 11.2.1) and Properties;
 * a datagram has no Subgroup ID, so a set naming one passes none. */
int moqtrun_sub_dg_pass(
    const wired_moqtrun_sub* s, const moqdg_obj* o, u8 dflt) {
  u64              prio = moqdg_type_default_prio(o->type) ? dflt : o->priority;
  moqtrun_fsel_obj f    = {{0, o->object_id, prio}, o->props, 2 | 4, 1};
  return moqtrun_fsel_pass(s->rngf, s->rngf_n, &f);
}

/* s's Range Filters can cut single Objects out of a stream. */
int moqtrun_sub_cuts_objects(const wired_moqtrun_sub* s) {
  for (usz i = 0; i < s->rngf_n; i++) {
    if (moqtrun_ofilt_row_cuts(&s->rngf[i])) {
      return 1;
    }
  }
  return 0;
}

/* s rides a reliable relay's ring: a ring carries one byte sequence for
 * every cursor, so a subscription cut per Object is served per round
 * instead (moqtrun_relay_append_cut). */
int moqtrun_sub_rides_ring(const wired_moqtrun_sub* s) {
  return moqtrun_sub_forwards(s) && !moqtrun_sub_cuts_objects(s);
}

/* Slot i takes relay's Objects re-chained: its Range Filters cut Objects
 * now, or did on this stream before (sub_cut holds until it ends, so a
 * filter removed mid-stream keeps the re-chained Deltas consistent). */
int moqtrun_ofilt_cutting(
    const wired_moqtrun_relay* relay, usz i, const wired_moqtrun_sub* s) {
  return (relay->sub_cut >> i & 1) || moqtrun_sub_cuts_objects(s);
}

/* Object id, rest being all of it past its ID Delta, appended to out at
 * *n under a Delta chained from *d; 0 when it does not fit (the buffers
 * are sized so a filtered round always fits, moqtrun.h). */
int moqtrun_rechain_put(
    wired_mspan out, usz* n, moqdata_objseq* d, u64 id, wired_span rest) {
  u64 delta = d->have_prev ? id - d->prev_id - 1 : id;
  if (out.n - *n < moqvi_len(delta) + rest.n) {
    return 0;
  }
  *n += moqvi_encode(out.p + *n, delta);
  bytes_memcpy(out.p + *n, rest.p, rest.n);
  *n += rest.n;
  d->have_prev = 1;
  d->prev_id   = id;
  return 1;
}

/* Sub slot i's chain once wire (Objects decoded from seq) was sent on
 * its stream: at wire's last Object, if any. A no-op for a slot not cut
 * per Object. */
void moqtrun_ofilt_sent(
    wired_moqtrun_relay* relay, usz i, wired_span wire, moqdata_objseq seq) {
  usz         at = 0;
  moqdata_obj o  = {0};
  if (!(relay->sub_cut >> i & 1)) {
    return;
  }
  while (moqdata_obj_take(wire, &at, &seq, &o) == MOQDATA_OK) {
    relay->sub_dprev[i] = o.object_id;
    relay->sub_dhave |= moqtrun_sub_bit(i);
  }
}

/* Slot i, ring-backed, was cut per Object: it has no ring cursor. */
int moqtrun_ofilt_ring_cut(const wired_moqtrun_relay* relay, usz i) {
  return relay->rel_idx >= 0 && (relay->sub_cut >> i & 1);
}

/* Slot i's stream (re)opened is cut per Object: sub's Range Filters cut
 * Objects, or it reopens beside a ring it never rode (a reset after a
 * refusal, moqtrun_ofilt_refused). */
static int moqtrun_ofilt_stays(
    const wired_moqtrun_relay* relay, usz i, const wired_moqtrun_sub* sub) {
  return moqtrun_sub_cuts_objects(sub) || moqtrun_ofilt_ring_cut(relay, i);
}

/* Sub slot i's stream just opened carrying out (a SUBGROUP_HEADER, then
 * Objects): cut per Object from here on when sub's Range Filters can,
 * chained at out's last Object. */
void moqtrun_ofilt_opened(
    wired_moqtrun_relay*     relay,
    usz                      i,
    const wired_moqtrun_sub* sub,
    wired_span               out) {
  usz            off = 0;
  moqdata_subhdr h;
  int            cut = moqtrun_ofilt_stays(relay, i, sub);
  relay->sub_dhave &= ~moqtrun_sub_bit(i);
  relay->sub_cut &= ~moqtrun_sub_bit(i);
  if (!cut || moqdata_subhdr_take(out, &off, &h) != MOQDATA_OK) {
    return;
  }
  relay->sub_cut |= moqtrun_sub_bit(i);
  moqtrun_ofilt_sent(
      relay, i, wired_span_of(out.p + off, out.n - off),
      moqdata_objseq_of(h.type));
}
