#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_upf_obj_of(
    moqfetch_obj* d, const moqfetch_obj* o, const moqfetch_seq* s);
static int moqtrun_upf_send_item(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, usz n);
static int moqtrun_upf_append(wired_moqt_hub* hub, usz* n, wired_span pre);
static int moqtrun_upf_encode(
    wired_moqt_hub*     hub,
    const moqfetch_obj* d,
    moqfetch_seq*       seq,
    wired_span          pre,
    usz*                n);
static int moqtrun_upf_write(
    wired_moqt_hub*      hub,
    wired_moqtrun_fetch* f,
    const moqfetch_obj*  o,
    wired_span           pre);
static int moqtrun_upf_same_at(wired_span c, u64 len, u64 at, wired_span part);

/* o as the downstream stream s's next item (draft-22 7.8: no field
 * changes, only how the flags reference the prior item). */
static void moqtrun_upf_obj_of(
    moqfetch_obj* d, const moqfetch_obj* o, const moqfetch_seq* s) {
  *d       = *o;
  d->flags = o->flags >= 0x80 ? moqtrun_upf_eor_of(o->flags, s)
                              : moqtrun_upf_flags_of(o, s);
}

/* The n encoded bytes written out on f's stream, opened with the first
 * item. */
static int moqtrun_upf_send_item(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, usz n) {
  return moqtrun_fetch_open(hub, f) &&
         hub->io.stream_send(
             f->wt, f->stream_id, wired_span_of(hub->relay_scratch, n), 0) > 0;
}

/* pre appended to the n bytes staged in relay_scratch; 0 if it overflows. */
static int moqtrun_upf_append(wired_moqt_hub* hub, usz* n, wired_span pre) {
  if (*n + pre.n > sizeof hub->relay_scratch) return 0;
  bytes_memcpy(hub->relay_scratch + *n, pre.p, pre.n);
  *n += pre.n;
  return 1;
}

/* d's head, then pre, staged in relay_scratch (*n bytes). */
static int moqtrun_upf_encode(
    wired_moqt_hub*     hub,
    const moqfetch_obj* d,
    moqfetch_seq*       seq,
    wired_span          pre,
    usz*                n) {
  return moqfetch_obj_put_head(
             wired_mspan_of(hub->relay_scratch, sizeof hub->relay_scratch), n,
             seq, d) &&
         moqtrun_upf_append(hub, n, pre);
}

/* o's head and pre relayed downstream now, in one write: pre is the
 * whole payload of a small Object, none of a large one's -- that passes
 * through after as it arrives (moqtrun_upf_pass); 0 when the transport
 * refused the write. */
static int moqtrun_upf_write(
    wired_moqt_hub*      hub,
    wired_moqtrun_fetch* f,
    const moqfetch_obj*  o,
    wired_span           pre) {
  moqfetch_obj d;
  moqfetch_seq seq = f->seq;
  usz          n   = 0;
  moqtrun_upf_obj_of(&d, o, &seq);
  if (!moqtrun_upf_encode(hub, &d, &seq, pre, &n) ||
      !moqtrun_upf_send_item(hub, f, n))
    return 0;
  f->seq         = seq;
  f->up_last     = moqtrun_upf_loc(o);
  f->has_up_last = 1;
  f->up_pl_at    = pre.n;
  f->up_pl_left  = o->payload.n - pre.n;
  f->last_ok_ms  = hub->live.last_now_ms;
  return 1;
}

int moqtrun_upf_relay(
    wired_moqt_hub*      hub,
    wired_moqtrun_fetch* f,
    const moqfetch_obj*  o,
    wired_span           pre) {
  return moqtrun_upf_valid(f, moqtrun_upf_loc(o)) &&
         moqtrun_upf_write(hub, f, o, pre);
}

/* ----- Malformed Track (draft-22 12.1) ----- */

/* The held track f serves, else 0. */
wired_moqtrun_track* moqtrun_upf_track(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f) {
  return f->cache_tag ? moqtrun_pubst_track(hub, f->cache_tag) : 0;
}

/* #5: past the final Object of a track whose End Of Track FETCH_OK said. */
int moqtrun_upf_past_end(const wired_moqtrun_fetch* f, moqctl_loc l) {
  return f->up_state == WIRED_MOQTRUN_UPF_OK && f->up_eot &&
         moqctl_loc_less(f->up_end, l);
}

/* A cached payload c of len bytes whose bytes from at on are part. */
static int moqtrun_upf_same_at(wired_span c, u64 len, u64 at, wired_span part) {
  return c.n == len && moqtrun_bytes_eq(c.p + at, part.p, part.n);
}

/* #6: the cache holds the Object at l with another payload than one of
 * len bytes whose bytes from at on are part (the cache keeps nothing
 * else of an Object to compare). */
int moqtrun_upf_conflicts(
    wired_moqt_hub*            hub,
    const wired_moqtrun_fetch* f,
    moqctl_loc                 l,
    u64                        len,
    u64                        at,
    wired_span                 part) {
  moqcache_item it;
  moqcache_item_at(&hub->cache, f->cache_tag, l, moqtrun_after(l), &it);
  return !it.unknown && !moqtrun_upf_same_at(it.payload, len, at, part);
}
