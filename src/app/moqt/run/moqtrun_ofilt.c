#include "app/moqt/run/moqtrun_impl.h"

/* ===== Range Filters per Object on a relayed Subgroup stream =====
 * draft-19 5.1.3/5.1.4, draft-22/23 3.3.2/3.3.3: "The publisher MUST
 * forward only objects that pass all filters". SUBGROUP_FILTER and
 * PRIORITY_FILTER judge a whole stream (moqtrun_sub_rngf_stream); a
 * subscription with OBJECTID_FILTER or OBJECT_PROPERTY_FILTER rows has
 * every Object judged against all its sets (moqtrun_fsel_pass) and its
 * stream re-encoded: each kept Object's ID Delta chains onto the last
 * Object kept (draft-19 11.4.2, draft-22/23 11.3.1: Delta + 1 is added
 * to the previous Object ID on the stream, the first one is absolute).
 * Unfiltered subscribers keep the publisher's bytes. A stream with no
 * kept Object is not opened; it opens on its first kept Object. Its head
 * has END_OF_GROUP cleared: a cut tail would let the FIN claim a last
 * Object the Group does not end at (draft-22/23 11.3.1, 12.1 #4). */

typedef struct {
  const wired_moqtrun_sub* s;
  /** The stream's Subgroup ID and Publisher Priority. */
  u64 sg;
  u8  prio;
  /** Where kept Objects go; n bytes written. Empty for a dry run. */
  wired_mspan out;
  usz         n;
  /** Downstream chain: the last Object kept. */
  moqdata_objseq dseq;
  /** Objects that passed (written or not). */
  usz kept;
  /** 1 once an Object was cut before any was kept. */
  int lead_cut;
} moqtrun_ofilt_ctx;

static int moqtrun_ofilt_pass(const moqtrun_ofilt_ctx* c, const moqdata_obj* o);
static void moqtrun_ofilt_step(
    moqtrun_ofilt_ctx* c, wired_span w, usz from, usz at, const moqdata_obj* o);
static void moqtrun_ofilt_walk(
    moqtrun_ofilt_ctx* c, wired_span w, moqdata_objseq pub);
static wired_span moqtrun_ofilt_prepend(
    wired_moqt_hub* hub, moqdata_subhdr h, u64 sg, int lead_cut, usz n);
static wired_span moqtrun_ofilt_head(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* s,
    wired_span               wire,
    u64                      group,
    u64                      sg,
    u8                       prio,
    int*                     bare);
static moqtrun_ofilt_ctx moqtrun_ofilt_ctx_of(
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_relay* relay,
    usz                        i,
    wired_mspan                out,
    int                        has_props);

static int moqtrun_ofilt_pass(
    const moqtrun_ofilt_ctx* c, const moqdata_obj* o) {
  moqtrun_fsel_obj f = {
      {c->sg, o->object_id, c->prio}, o->props, 7, (u8)c->dseq.has_props};
  return moqtrun_fsel_pass(c->s->rngf, c->s->rngf_n, &f);
}

/* The Object w[from..at): kept (re-chained) when it passes.
 * One that does not fit is cut, its successor chained past it -- not
 * reached: the scratch has WIRED_MOQTRUN_OFILT_SLACK past a round. */
static void moqtrun_ofilt_step(
    moqtrun_ofilt_ctx* c,
    wired_span         w,
    usz                from,
    usz                at,
    const moqdata_obj* o) {
  usz dl = from;
  u64 d;
  if (!moqtrun_ofilt_pass(c, o)) {
    c->lead_cut |= !c->dseq.have_prev;
    return;
  }
  c->kept++;
  moqvi_take(w, &dl, &d);
  moqtrun_rechain_put(
      c->out, &c->n, &c->dseq, o->object_id, wired_span_of(w.p + dl, at - dl));
}

/* Every Object of w, decoded from the publisher's chain pub. */
static void moqtrun_ofilt_walk(
    moqtrun_ofilt_ctx* c, wired_span w, moqdata_objseq pub) {
  usz         at = 0, from;
  moqdata_obj o  = {0};
  for (from = 0; moqdata_obj_take(w, &at, &pub, &o) == MOQDATA_OK; from = at) {
    moqtrun_ofilt_step(c, w, from, at, &o);
  }
}

/* Objects at relay_scratch[HDR_MAX..+n) under h, or a late head
 * (moqtrun_late_hdr_of) when the stream's first Object was cut, either
 * without END_OF_GROUP; head and Objects as one span. */
static wired_span moqtrun_ofilt_prepend(
    wired_moqt_hub* hub, moqdata_subhdr h, u64 sg, int lead_cut, usz n) {
  u8  hdr[WIRED_MOQTRUN_RELAY_HDR_MAX];
  usz k = 0;
  h.type &= ~0x08ULL;
  if (lead_cut) {
    k = moqtrun_late_hdr_of(h, sg, hdr);
  } else {
    moqdata_subhdr_put(wired_mspan_of(hdr, sizeof hdr), &k, &h);
  }
  u8* at = hub->relay_scratch + WIRED_MOQTRUN_RELAY_HDR_MAX - k;
  bytes_memcpy(at, hdr, k);
  return wired_span_of(at, k + n);
}

/* moqtrun_head_startobj_cut for a subscriber cut per Object: wire's
 * Objects past s's start Object that pass, re-chained under their head
 * in hub->relay_scratch. *bare when none passes. */
static wired_span moqtrun_ofilt_head(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* s,
    wired_span               wire,
    u64                      group,
    u64                      sg,
    u8                       prio,
    int*                     bare) {
  usz            off = 0;
  moqdata_subhdr h;
  *bare = 0;
  if (moqdata_subhdr_take(wire, &off, &h) != MOQDATA_OK) {
    return wire;
  }
  moqdata_objseq    seq = moqdata_objseq_of(h.type);
  usz               cut = moqtrun_startobj_cut(s, wire, off, &seq, group);
  moqtrun_ofilt_ctx c   = {
      s,
      sg,
      prio,
      wired_mspan_of(
          hub->relay_scratch + WIRED_MOQTRUN_RELAY_HDR_MAX,
          sizeof hub->relay_scratch - WIRED_MOQTRUN_RELAY_HDR_MAX),
      0,
      moqdata_objseq_of(h.type),
      0,
      cut != off};
  moqtrun_ofilt_walk(&c, wired_span_of(wire.p + cut, wire.n - cut), seq);
  *bare = c.n == 0;
  return moqtrun_ofilt_prepend(hub, h, sg, c.lead_cut, c.n);
}

/* A stream's opening bytes as s receives them: cut per Object when its
 * Range Filters can (moqtrun_ofilt_head), else to its start Object only
 * (moqtrun_head_startobj_cut). */
wired_span moqtrun_sub_head(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* s,
    wired_span               wire,
    u64                      group,
    u64                      sg,
    u8                       prio,
    int*                     bare) {
  if (moqtrun_sub_cuts_objects(s)) {
    return moqtrun_ofilt_head(hub, s, wire, group, sg, prio, bare);
  }
  return moqtrun_head_startobj_cut(hub, s, wire, group, sg, bare);
}

/* A round's Objects as sub slot i's rounds see them; out empty for a
 * dry run. */
static moqtrun_ofilt_ctx moqtrun_ofilt_ctx_of(
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_relay* relay,
    usz                        i,
    wired_mspan                out,
    int                        has_props) {
  moqtrun_ofilt_ctx c = {
      s,
      relay->subgroup_id,
      relay->pub_prio,
      out,
      0,
      {has_props, (int)(relay->sub_dhave >> i & 1), relay->sub_dprev[i]},
      0,
      0};
  return c;
}

/* 1 when some Object of r passes for sub slot i. */
int moqtrun_ofilt_keeps(
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_relay* relay,
    usz                        i,
    moqtrun_round              r) {
  moqtrun_ofilt_ctx c =
      moqtrun_ofilt_ctx_of(s, relay, i, wired_mspan_of(0, 0), r.seq0.has_props);
  moqtrun_ofilt_walk(&c, r.wire, r.seq0);
  return c.kept != 0;
}

/* r for sub slot i: its passing Objects re-chained in hub->alias_scratch
 * (sized like a relay round plus a re-spelled alias), seq0 the chain
 * they decode from. */
moqtrun_round moqtrun_ofilt_round(
    wired_moqt_hub*            hub,
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_relay* relay,
    usz                        i,
    moqtrun_round              r) {
  moqtrun_ofilt_ctx c = moqtrun_ofilt_ctx_of(
      s, relay, i,
      wired_mspan_of(hub->alias_scratch, sizeof hub->alias_scratch),
      r.seq0.has_props);
  moqdata_objseq d0 = c.dseq;
  moqtrun_ofilt_walk(&c, r.wire, r.seq0);
  moqtrun_round out = {wired_span_of(hub->alias_scratch, c.n), d0, r.fin};
  return out;
}
