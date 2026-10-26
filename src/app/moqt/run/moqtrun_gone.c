#include "app/moqt/run/moqtrun_impl.h"

/* draft-18/19 9.1 on a Subgroup stream: "an endpoint can receive an Object
 * after it has already recorded that the Object does not exist. A caching
 * relay SHOULD NOT cache or forward the Object in this case." Such an
 * Object (moqtrun_obj_gone) is cut out of the forwarded bytes, and the
 * next kept Object's Object ID Delta re-chained onto the last one sent
 * (draft-18/19 11.4.2, draft-22 11.3.1). A stream whose first Object is
 * one is not relayed at all: its header may name that Object
 * (FIRST_OBJECT, a mode-0b01 Subgroup ID). */

typedef struct {
  wired_moqt_hub*            hub;
  const wired_moqtrun_track* track;
  /** The stream's Group ID. */
  u64 group;
  /** Downstream chaining state: the last Object kept. */
  moqdata_objseq dseq;
  /** Bytes written to hub->alias_scratch. */
  usz n;
  /** Set when the result cannot be relayed framed: an out-of-room
   * write, or a nonexistent Object before any was sent. */
  int poison;
  /** 1 while the next Object is kept regardless: its first bytes were
   * already sent ahead of its completion (moqtrun_cut.c). */
  int keep;
} moqtrun_gone_ctx;

static int  moqtrun_gone_put(moqtrun_gone_ctx* c, u64 id, wired_span rest);
static int  moqtrun_gone_drops(moqtrun_gone_ctx* c, u64 id);
static usz  moqtrun_gone_cut_at(usz from, usz head);
static void moqtrun_gone_step(
    moqtrun_gone_ctx* c, wired_span whole, usz from, usz at, u64 id);
static int moqtrun_gone_none(
    const wired_moqtrun_track* t,
    const wired_moqtrun_relay* relay,
    moqdata_objseq             pub0);
static wired_span moqtrun_gone_filter(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    wired_moqtrun_relay*       relay,
    wired_span                 whole,
    moqdata_objseq             pub0);

/* One kept Object as rest (all of it past its ID Delta) under a delta
 * re-chained from c->dseq, appended to hub->alias_scratch; 0 when it
 * does not fit in a relay round. */
static int moqtrun_gone_put(moqtrun_gone_ctx* c, u64 id, wired_span rest) {
  u64 delta = c->dseq.have_prev ? id - c->dseq.prev_id - 1 : id;
  if (sizeof c->hub->relay_scratch - c->n < 8 + rest.n) {
    return 0;
  }
  c->n += moqvi_encode(c->hub->alias_scratch + c->n, delta);
  bytes_memcpy(c->hub->alias_scratch + c->n, rest.p, rest.n);
  c->n += rest.n;
  c->dseq.have_prev = 1;
  c->dseq.prev_id   = id;
  return 1;
}

/* The Object with ID id is cut: recorded nonexistent and not already
 * partly sent. */
static int moqtrun_gone_drops(moqtrun_gone_ctx* c, u64 id) {
  int keep = c->keep;
  c->keep  = 0;
  return !keep &&
         moqtrun_obj_gone(c->hub, c->track, moqctl_loc_of(c->group, id));
}

/* The Object whole[from..at) with ID id: kept (re-chained) unless the
 * hub records it nonexistent. */
static void moqtrun_gone_step(
    moqtrun_gone_ctx* c, wired_span whole, usz from, usz at, u64 id) {
  usz dl = from;
  u64 d;
  if (moqtrun_gone_drops(c, id)) {
    c->poison |= !c->dseq.have_prev;
    return;
  }
  moqvi_take(whole, &dl, &d);
  c->poison |= !moqtrun_gone_put(c, id, wired_span_of(whole.p + dl, at - dl));
}

/* Nothing to cut: downstream still mirrors the publisher's chain and
 * the Group is open (moqtrun_obj_gone needs a closed one). */
static int moqtrun_gone_none(
    const wired_moqtrun_track* t,
    const wired_moqtrun_relay* relay,
    moqdata_objseq             pub0) {
  return moqtrun_cut_aligned(relay->dseq, pub0) &&
         !(t->has_largest && relay->group_id < t->largest.group);
}

/* whole (relay_scratch[0..), decoded from pub0) rewritten in place
 * through alias_scratch; a poisoned result leaves the relay poisoned
 * and nothing to send (moqtrun_relay_end_poisoned resets downstream). */
static wired_span moqtrun_gone_filter(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    wired_moqtrun_relay*       relay,
    wired_span                 whole,
    moqdata_objseq             pub0) {
  moqtrun_gone_ctx c   = {hub, t, relay->group_id,       relay->dseq,
                          0,   0, moqtrun_cut_any(relay)};
  usz              at  = 0, from;
  moqdata_obj      obj = {0};
  for (from = 0; moqdata_obj_take(whole, &at, &pub0, &obj) == MOQDATA_OK;
       from = at) {
    moqtrun_gone_step(&c, whole, from, at, obj.object_id);
  }
  if (c.poison) {
    moqtrun_frag_release(relay);
    moqtrun_frag_drop(hub, relay, 1);
    return wired_span_of(hub->relay_scratch, 0);
  }
  relay->dseq = c.dseq;
  bytes_memcpy(hub->relay_scratch, hub->alias_scratch, c.n);
  return wired_span_of(hub->relay_scratch, c.n);
}

/* A normalized round: whole (decoded from the publisher's chain pub0
 * in *seq0) with nonexistent Objects cut out; *seq0 becomes the
 * downstream chain the result decodes from (the per-subscriber cuts'
 * starting point). */
wired_span moqtrun_gone_round(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    wired_moqtrun_relay*       relay,
    wired_span                 whole,
    moqdata_objseq*            seq0) {
  moqdata_objseq pub0 = *seq0;
  *seq0               = relay->dseq;
  if (moqtrun_gone_none(t, relay, pub0)) {
    relay->dseq = relay->seq;
    return whole;
  }
  return moqtrun_gone_filter(hub, t, relay, whole, pub0);
}

/* 0 for a cut at the stream's first Object (offset head). */
static usz moqtrun_gone_cut_at(usz from, usz head) {
  return from == head ? 0 : from;
}

/* A fresh stream's opening bytes wire[0..end) (SUBGROUP_HEADER, Objects):
 * end, or the offset of its first nonexistent Object -- the bytes from
 * there wait as the relay's fragment, cut by the next round's
 * moqtrun_gone_round -- and 0 when that is its first Object (not
 * relayed). */
usz moqtrun_gone_head_cut(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    wired_span                 wire,
    usz                        end) {
  usz            at = 0, from;
  moqdata_subhdr h;
  moqdata_obj    obj = {0};
  moqdata_subhdr_take(wire, &at, &h);
  moqdata_objseq seq  = moqdata_objseq_of(h.type);
  usz            head = at;
  wired_span     w    = wired_span_of(wire.p, end);
  for (from = at; moqdata_obj_take(w, &at, &seq, &obj) == MOQDATA_OK;
       from = at) {
    if (moqtrun_obj_gone(hub, t, moqctl_loc_of(h.group_id, obj.object_id))) {
      return moqtrun_gone_cut_at(from, head);
    }
  }
  return end;
}

/* A one-shot stream (its FIN came with its first delivery) relayed up to
 * its first nonexistent Object; nothing when that is its first.
 * shortcut: Objects after that one are not relayed either -- in the
 * closed Group a nonexistent Object implies, only an Object the cache
 * already holds can follow; re-chain them (moqtrun_gone_filter) through
 * a scratch of their own if that ever matters. */
void moqtrun_relay_object_cut(
    wired_moqt_hub* hub, wired_moqtrun_track* track, wired_span wire) {
  usz cut = moqtrun_gone_head_cut(hub, track, wire, wire.n);
  if (cut) {
    moqtrun_relay_object(hub, track, wired_span_of(wire.p, cut));
  }
}
