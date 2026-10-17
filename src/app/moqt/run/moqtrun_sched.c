#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_ssts_hub_track(
    const wired_moqt_hub* hub, const moqctl_subscribe* m);
static int moqtrun_ssts_unsettable(
    const wired_moqt_hub*     hub,
    const wired_moqtrun_peer* p,
    const moqctl_subscribe*   m);
static void moqtrun_subscribe_checked(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m,
    wired_span              body);
static void moqtrun_sched_legacy(
    wired_moqt_hub*       hub,
    wired_wt_session*     wt,
    u64                   sid,
    const wired_wt_sched* k);

/* SSTS (moqtssts_run.c): m names one of the hub's own tracks (blob /
 * live), which no switching set may hold. */
static int moqtrun_ssts_hub_track(
    const wired_moqt_hub* hub, const moqctl_subscribe* m) {
  return moqtrun_track_name_matches(&hub->blob_track, m->name.name) ||
         moqtrun_track_name_matches(&hub->live.track, m->name.name);
}

/* SSTS (moqtssts_run.c): a SUBSCRIBE that may not join a switching set --
 * to a hub track, or on the control stream (p->req 0): such a
 * subscription re-attaches silently to a re-PUBLISHed track, whose group
 * numbers restart under a set that may have been pruned meanwhile. */
static int moqtrun_ssts_unsettable(
    const wired_moqt_hub*     hub,
    const wired_moqtrun_peer* p,
    const moqctl_subscribe*   m) {
  return moqtrun_ssts_hub_track(hub, m) || !p->req;
}

/* draft SS10.6 SUBSCRIBE: refuse it per moqtrun_subscribe_refusal
 * (reserved namespace, bad Range/Location Filter, alias token or
 * unauthorized subscriber -- any SUBGROUP_DELIVERY_TIMEOUT is accepted,
 * 10.2.3), else delegate matching + response to moqtrun_route_subscribe. */
static void moqtrun_subscribe_checked(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m,
    wired_span              body) {
  if (moqtrun_fill_malformed(hub, p, &m->params)) return;
  u64 code = moqtsw_sub_refusal( /* SWITCH_FROM: never on a hub track */
      &m->params, moqtrun_ssts_hub_track(hub, m),
      moqtss_sub_refusal( /* SSTS (moqtssts_run.c) */
          &m->params, moqtrun_ssts_unsettable(hub, p, m),
          moqtrun_subscribe_refusal(hub, m)));
  if (code != MOQTRUN_REQ_ACCEPT) {
    moqtrun_send_request_error(p, code);
    return;
  }
  moqtrun_route_subscribe(hub, p, peer_idx, m, body);
}

void moqtrun_handle_subscribe(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  usz              off = 0;
  moqctl_subscribe m;
  if (!moqtrun_take_tok_or_close(
          hub, p,
          moqtss_take(
              hub,
              moqtsw_take( /* SWITCH_FROM (moqtswitch.c): off = violation */
                  hub, moqctl_subscribe_take(p->ver, body, &off, &m),
                  &m.params),
              &m.params),
          &m.params))
    return;
  moqtrun_subscribe_checked(hub, p, peer_idx, &m, body);
}

/* ============ Object stream send classes (draft-22 7.2) ============ */

/* draft-ietf-moq-transport-19 10.2.7: SUBSCRIBER_PRIORITY defaults to
 * 128. */
u8 moqtrun_sub_prio(const wired_moqtrun_sub* s) {
  return s->has_priority ? s->priority : 128;
}

/* The flow of request rid on peer slot idx: a subscription and its fill
 * share it, a FETCH has its own (Request IDs are unique per session).
 * ponytail: Request IDs past 2^56 alias another; widen if one gets there. */
u64 moqtrun_flow_of(usz idx, u64 rid) {
  return (u64)(idx + 1) << 56 | (rid & ((1ULL << 56) - 1));
}

/* Group g's rank inside its flow, lowest first (7.2 rule 3). */
u64 moqtrun_group_rank(int descending, u64 g) { return descending ? ~g : g; }

/* An Object stream's class: Subscriber, then Publisher Priority (7.2
 * rules 1-2), then (order, tie) inside its flow. */
wired_wt_sched moqtrun_sched_of(
    u8 sub_prio, u8 pub_prio, u64 flow, u64 order, u64 tie) {
  wired_wt_sched k = {
      MOQTRUN_OBJ_URGENCY, (u16)(sub_prio << 8 | pub_prio), flow, order, tie};
  return k;
}

/* A subscription-delivered stream of s in Group group, Subgroup sg. */
wired_wt_sched moqtrun_sub_key(
    const wired_moqtrun_sub* s, u8 pub_prio, u64 group, u64 sg) {
  return moqtrun_sched_of(
      moqtrun_sub_prio(s), pub_prio,
      moqtrun_flow_of(s->session_idx, s->request_id),
      moqtrun_group_rank(s->group_order == MOQTRUN_ORDER_DESC, group),
      MOQTRUN_TIE_LIVE | sg);
}

/* A table without stream_sched: the coarse urgency alone. */
static void moqtrun_sched_legacy(
    wired_moqt_hub*       hub,
    wired_wt_session*     wt,
    u64                   sid,
    const wired_wt_sched* k) {
  if (!hub->io.stream_priority) return;
  hub->io.stream_priority(
      wt, sid, WIRED_MOQTRUN_URGENCY(k->fine >> 8, k->fine & 0xff));
}

/* Sets k on stream sid (nothing when the open failed, sid < 0). */
void moqtrun_sched_apply(
    wired_moqt_hub*       hub,
    wired_wt_session*     wt,
    i64                   sid,
    const wired_wt_sched* k) {
  if (sid < 0) return;
  if (hub->io.stream_sched) {
    hub->io.stream_sched(wt, (u64)sid, k);
    return;
  }
  moqtrun_sched_legacy(hub, wt, (u64)sid, k);
}
