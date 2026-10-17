#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_set_stream_pass(
    const wired_moqtrun_sub* s, u8 set, u64 sg, u64 prio);
static u64 moqtrun_sub_sgt(
    const wired_moqtrun_track* t, const moqctl_subscribe* m);
static int moqtrun_sub_in_range(const wired_moqtrun_sub* s, u64 g);

/* SetIDs OR together (10.2.10): the Object passes when any set's
 * evaluable params all admit it; no rows at all is unfiltered. */
int moqtrun_sub_rngf_pass(const wired_moqtrun_sub* s, u64 oid) {
  int pass = !s->rngf_n; /* no rows: unfiltered */
  for (usz i = 0; i < s->rngf_n; i++)
    pass |= moqtrun_set_dim_pass(
        s, s->rngf[i].set_id, MOQCTL_PARAM_OBJECTID_FILTER, oid);
  return pass;
}

/* One set's SUBGROUP_FILTER and PRIORITY_FILTER (d22 9.20.10/9.20.12,
 * AND'd within the set) for a stream of Subgroup sg, Publisher Priority
 * prio. */
static int moqtrun_set_stream_pass(
    const wired_moqtrun_sub* s, u8 set, u64 sg, u64 prio) {
  return moqtrun_set_dim_pass(s, set, MOQCTL_PARAM_SUBGROUP_FILTER, sg) &
         moqtrun_set_dim_pass(s, set, MOQCTL_PARAM_PRIORITY_FILTER, prio);
}

/* The stream-level Range Filter gate, evaluated when a stream opens
 * toward s: Subgroup ID and Publisher Priority are the stream header's.
 * Object-level filters are not cut on streams (OBJECTID gates datagrams
 * only), so a set with only those passes here. */
int moqtrun_sub_rngf_stream(const wired_moqtrun_sub* s, u64 sg, u64 prio) {
  int pass = !s->rngf_n;
  for (usz i = 0; i < s->rngf_n; i++)
    pass |= moqtrun_set_stream_pass(s, s->rngf[i].set_id, sg, prio);
  return pass;
}

/* min over the non-zero of {publisher's Track Property, subscriber's
 * parameter} (draft-19 8); 0 = neither set a timeout. */
u64 moqtrun_timeout_min(u64 pub_ms, u64 sub_ms) {
  if (!pub_ms) return sub_ms;
  if (!sub_ms) return pub_ms;
  return u64_min(pub_ms, sub_ms);
}

static u64 moqtrun_sub_sgt(
    const wired_moqtrun_track* t, const moqctl_subscribe* m) {
  return moqtrun_timeout_min(
      t->subgroup_timeout_ms, moqtrun_param_vi(moqtrun_sub_param(
                                  m, MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT)));
}

/* Opens slot s on t for peer_idx under alias, its state taken from
 * SUBSCRIBE m. */
void moqtrun_sub_open(
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    usz                        peer_idx,
    u64                        alias,
    const moqctl_subscribe*    m) {
  s->session_idx  = peer_idx;
  s->track_alias  = alias;
  s->active       = 1;
  s->request_id   = m->request_id;
  s->blob_sent    = 0;
  s->stream_count = 0;
  s->newest_sid   = 0;
  s->no_props     = moqtrun_sub_no_props(m);
  moqtss_sub_reset(s); /* SSTS (moqtssts_run.c): in no set */
  moqtsw_sub_clear(s); /* SWITCH_FROM (moqtswitch.c): no switch */
  s->jl     = t->largest;
  s->has_jl = (u8)t->has_largest;
  moqtrun_sub_scalars(s, m);
  s->subgroup_timeout = moqtrun_sub_sgt(t, m);
  moqtrun_sub_rngf_set(s, &m->params);
  moqtrun_sub_filter(s, t, moqtrun_sub_param(m, MOQCTL_PARAM_LOCATION_FILTER));
}

/* 1 iff Objects go to s: Established and not FORWARD 0 (10.2.17). */
int moqtrun_sub_forwards(const wired_moqtrun_sub* s) {
  return s->active && !s->forward_off;
}

/* 1 iff Group g passes s's Location Filter (5.1.4): not before the start
 * Group, not past the end Group. */
static int moqtrun_sub_in_range(const wired_moqtrun_sub* s, u64 g) {
  return g >= s->start.group && !(s->has_end_group && g > s->end_group);
}

/* Location Filter, and the SSTS forward gate (moqtss_sub_pass): a
 * switching-set member takes only the Groups decided for its track. */
int moqtrun_sub_wants_group(const wired_moqtrun_sub* s, u64 g) {
  return moqtrun_sub_in_range(s, g) && moqtss_sub_pass(s, g);
}

/* 1 iff l is past an explicit End Object (draft-22 0x04) in its Group. */
int moqtrun_sub_past_end_object(const wired_moqtrun_sub* s, moqctl_loc l) {
  return s->has_end_object && l.group == s->end_group &&
         l.object > s->end_object;
}

/* Forward AND Location Filter (5.1.5) for a stream of Group g. Both
 * ends are cut per Object inside the Group: the start Object by
 * moqtrun_startobj_cut, a draft-22 End Object by moqtrun_wire_cutoff. */
int moqtrun_sub_gets(const wired_moqtrun_sub* s, u64 g) {
  return moqtrun_sub_forwards(s) && moqtrun_sub_wants_group(s, g);
}
