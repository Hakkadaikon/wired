#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_upd_forward(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p);
static void moqtrun_upd_priority(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p);
static void moqtrun_upd_timeout(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p);
static void moqtrun_upd_filter(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p);
static void moqtrun_upd_sgt(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p);
static void moqtrun_upd_ignore(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p);
static moqtrun_upd_fn moqtrun_upd_lookup(u64 type);

/* Peer idx's live subscription rid on any track, *t its track. */
wired_moqtrun_sub* moqtrun_hub_sub_by_rid(
    wired_moqt_hub* hub, usz idx, u64 rid, wired_moqtrun_track** t) {
  wired_moqtrun_sub* s = moqtrun_sub_by_rid(hub, idx, rid, t);
  if (s) return s;
  *t = &hub->blob_track;
  s  = moqtrun_live_track_sub_by_rid(*t, idx, rid);
  if (s) return s;
  *t = &hub->live.track;
  return moqtrun_live_track_sub_by_rid(*t, idx, rid);
}

/* The state p remembers for subscription rid (sub_names), else 0. */
wired_moqtrun_sub* moqtrun_sub_state_by_rid(wired_moqtrun_peer* p, u64 rid) {
  for (usz i = 0; i < p->sub_names_n; i++)
    if (p->sub_state[i].request_id == rid) return &p->sub_state[i];
  return 0;
}

/* The subscription to update: its live slot (*t its track), else -- its
 * publisher gone -- the state kept for its return (*t 0), else 0. */
wired_moqtrun_sub* moqtrun_upd_target(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    usz                   idx,
    wired_moqtrun_track** t) {
  wired_moqtrun_sub* s =
      moqtrun_hub_sub_by_rid(hub, idx, p->req->request_id, t);
  if (s) return s;
  *t = 0;
  return moqtrun_sub_state_by_rid(p, p->req->request_id);
}

static void moqtrun_upd_forward(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p) {
  (void)t;
  s->forward_off = moqtrun_forward_off(p);
}

static void moqtrun_upd_priority(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p) {
  (void)t;
  s->priority     = (u8)p->u8v;
  s->has_priority = 1;
}

static void moqtrun_upd_timeout(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p) {
  (void)t;
  s->delivery_timeout     = p->vi;
  s->has_delivery_timeout = 1;
}

static void moqtrun_upd_filter(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p) {
  moqtrun_sub_filter(s, t, p);
}

/* The update's SUBGROUP_DELIVERY_TIMEOUT re-mins against the publisher's
 * Track Property (t 0 while the publisher is away: no property side). */
static void moqtrun_upd_sgt(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p) {
  s->subgroup_timeout =
      moqtrun_timeout_min(t ? t->subgroup_timeout_ms : 0, p->vi);
}

/* Parameters in the update's scope this hub keeps no state for. */
static void moqtrun_upd_ignore(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p) {
  (void)s;
  (void)t;
  (void)p;
}

static const struct {
  u64            type;
  moqtrun_upd_fn fn;
} moqtrun_upd_table[] = {
    {MOQCTL_PARAM_FORWARD, moqtrun_upd_forward},
    {MOQCTL_PARAM_SUBSCRIBER_PRIORITY, moqtrun_upd_priority},
    {MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT, moqtrun_upd_timeout},
    {MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT, moqtrun_upd_sgt},
    {MOQCTL_PARAM_LOCATION_FILTER, moqtrun_upd_filter},
};

static moqtrun_upd_fn moqtrun_upd_lookup(u64 type) {
  for (usz i = 0; i < sizeof moqtrun_upd_table / sizeof moqtrun_upd_table[0];
       i++)
    if (moqtrun_upd_table[i].type == type) return moqtrun_upd_table[i].fn;
  return moqtrun_upd_ignore;
}

/* FORWARD went 0 -> 1 on a live subscription. */
int moqtrun_upd_turned_on(
    u8 was_off, const wired_moqtrun_sub* s, const wired_moqtrun_track* t) {
  return was_off && !s->forward_off && t;
}

/* draft 5.1: the Largest Location REQUEST_UPDATE_OK carries becomes the
 * Joining Location; the hub's blob, held back by FORWARD 0, goes out now.
 * 0 when that send is refused. */
int moqtrun_upd_forward_on(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t) {
  s->jl     = t->largest;
  s->has_jl = (u8)t->has_largest;
  if (t != &hub->blob_track || s->blob_sent) return 1;
  return moqtrun_blob_deliver(hub, p, s);
}

/* Present parameters replace, absent ones stay (10.9). */
void moqtrun_upd_params(
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params) {
  moqtrun_sub_rngf_update(s, params);
  for (usz i = 0; i < params->n; i++)
    moqtrun_upd_lookup(params->items[i].type)(s, t, &params->items[i]);
}
