#include "app/moqt/run/moqtrun_impl.h"

/* ===== NEW_GROUP_REQUEST relay handling (draft-18/19 10.2.13) =====
 * A relay forwards a downstream NEW_GROUP_REQUEST upstream: in its own
 * SUBSCRIBE when the Track has no Established subscription, else in a
 * REQUEST_UPDATE to the publisher -- for a value of 0 or above the
 * Largest Group, a Track with DYNAMIC_GROUPS 1, and no request of a
 * greater or equal value still outstanding (until the Largest Group
 * increases).
 * A Track the hub holds through its own upstream SUBSCRIBE gets it on
 * that stream, a PUBLISH-initiated one on the PUBLISH stream
 * (moqtrun_pubupd.c parses the publisher's answer there). */

static int moqtrun_ngr_waiter(const wired_moqtrun_rdv* r, moqtrun_key k);
static int moqtrun_ngr_enc_upd(wired_mspan buf, usz* off, const void* m);
static u64 moqtrun_ngr_group(const wired_moqtrun_track* t);
static int moqtrun_ngr_ahead(const wired_moqtrun_track* t, u64 v);
static int moqtrun_ngr_wanted(const wired_moqtrun_track* t, u64 v);
static int moqtrun_ngr_outstanding(
    const wired_moqtrun_ngr* s, const wired_moqtrun_track* t, u64 v);
static int moqtrun_ngr_due(
    const wired_moqtrun_ngr* s, const wired_moqtrun_track* t, u64 v);
static void moqtrun_ngr_mark(
    wired_moqtrun_ngr* s, const wired_moqtrun_track* t, u64 v);
static void moqtrun_ngr_send(
    wired_moqt_hub*            hub,
    wired_moqtrun_up*          u,
    const wired_moqtrun_track* t,
    u64                        v);
static void moqtrun_ngr_try(
    wired_moqt_hub*            hub,
    wired_moqtrun_up*          u,
    const wired_moqtrun_track* t,
    u64                        v);
static wired_moqtrun_ngr* moqtrun_ngr_st(wired_moqtrun_req* q);
static void               moqtrun_ngr_pub(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, u64 v);
static void moqtrun_ngr_route(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, u64 v);
/* Appends NEW_GROUP_REQUEST v to out. */
void moqtrun_ngr_add(moqctl_params* out, u64 v) {
  out->items[out->n].type = MOQCTL_PARAM_NEW_GROUP_REQUEST;
  out->items[out->n].enc  = MOQCTL_PENC_VARINT;
  out->items[out->n].vi   = v;
  out->n++;
}

/* 1 + *v when params carry a NEW_GROUP_REQUEST. */
u8 moqtrun_ngr_of(const moqctl_params* params, u64* v) {
  const moqctl_param* p =
      moqctl_params_find(params, MOQCTL_PARAM_NEW_GROUP_REQUEST);
  *v = moqtrun_param_vi(p);
  return p != 0;
}

static int moqtrun_ngr_waiter(const wired_moqtrun_rdv* r, moqtrun_key k) {
  return moqtrun_rdv_matches(r, k) && r->has_ngr;
}

/* The first waiter's NEW_GROUP_REQUEST for k rides the upstream
 * SUBSCRIBE (MUST). */
void moqtrun_ngr_upstream(
    const wired_moqt_hub* hub, moqtrun_key k, moqctl_params* out) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++) {
    if (moqtrun_ngr_waiter(&hub->rdv[i], k)) {
      moqtrun_ngr_add(out, hub->rdv[i].ngr);
      return;
    }
  }
}

static int moqtrun_ngr_enc_upd(wired_mspan buf, usz* off, const void* m) {
  return moqtstat_update_encode(buf, off, m);
}

/* t's Largest Group, ~0 while it has none. */
static u64 moqtrun_ngr_group(const wired_moqtrun_track* t) {
  return t->has_largest ? t->largest.group : ~(u64)0;
}

/* v is 0 or above t's Largest Group (any value while it has none). */
static int moqtrun_ngr_ahead(const wired_moqtrun_track* t, u64 v) {
  return v == 0 || !t->has_largest || v > t->largest.group;
}

/* t has dynamic Groups (DYNAMIC_GROUPS 1) and v asks past its Largest. */
static int moqtrun_ngr_wanted(const wired_moqtrun_track* t, u64 v) {
  return moqtrun_tprop(
             moqtrun_track_props(t), MOQTRUN_PROP_DYNAMIC_GROUPS, 0) == 1 &&
         moqtrun_ngr_ahead(t, v);
}

static int moqtrun_ngr_outstanding(
    const wired_moqtrun_ngr* s, const wired_moqtrun_track* t, u64 v) {
  return s->out && s->val >= v && s->group == moqtrun_ngr_group(t);
}

/* s (0: no stream to send on) owes t a REQUEST_UPDATE for v. */
static int moqtrun_ngr_due(
    const wired_moqtrun_ngr* s, const wired_moqtrun_track* t, u64 v) {
  return s && moqtrun_ngr_wanted(t, v) && !moqtrun_ngr_outstanding(s, t, v);
}

/* v went out for t: outstanding until t's Largest Group moves. */
static void moqtrun_ngr_mark(
    wired_moqtrun_ngr* s, const wired_moqtrun_track* t, u64 v) {
  s->out   = 1;
  s->val   = v;
  s->group = moqtrun_ngr_group(t);
}

/* REQUEST_UPDATE {params} under pp's next Request ID (consumes one,
 * 10.1) into msg; its length, 0 when it does not encode. */
usz moqtrun_upd_msg(
    wired_moqtrun_peer* pp, const moqctl_params* params, u8* msg, usz cap) {
  moqtstat_update m = {0};
  m.request_id      = pp->request_id_next;
  m.params          = *params;
  return moqtrun_envelope_put(
      wired_mspan_of(msg, cap), MOQTSTAT_T_REQUEST_UPDATE, moqtrun_ngr_enc_upd,
      &m);
}

/* REQUEST_UPDATE {NEW_GROUP_REQUEST v} on the hub's SUBSCRIBE stream; a
 * refused send leaves nothing outstanding. */
static void moqtrun_ngr_send(
    wired_moqt_hub*            hub,
    wired_moqtrun_up*          u,
    const wired_moqtrun_track* t,
    u64                        v) {
  u8                  msg[WIRED_MOQTRUN_CTL_REPLY_MAX];
  moqctl_params       params = {0};
  wired_moqtrun_peer* pp     = moqtrun_find_by_wt(hub, u->wt);
  moqtrun_ngr_add(&params, v);
  usz n = moqtrun_upd_msg(pp, &params, msg, sizeof msg);
  if (hub->io.stream_send(u->wt, u->stream_id, wired_span_of(msg, n), 0) != 1) {
    return;
  }
  pp->request_id_next += 2;
  u->upd_out++;
  moqtrun_ngr_mark(&u->ngr, t, v);
}

static void moqtrun_ngr_try(
    wired_moqt_hub*            hub,
    wired_moqtrun_up*          u,
    const wired_moqtrun_track* t,
    u64                        v) {
  if (moqtrun_ngr_due(u ? &u->ngr : 0, t, v)) {
    moqtrun_ngr_send(hub, u, t, v);
  }
}

/* q's NEW_GROUP_REQUEST state, 0 without a PUBLISH stream. */
static wired_moqtrun_ngr* moqtrun_ngr_st(wired_moqtrun_req* q) {
  return q ? &q->ngr : 0;
}

/* A PUBLISH-initiated t: the REQUEST_UPDATE rides the publisher's own
 * PUBLISH stream (draft-18 10.9: "A subscriber can also send
 * REQUEST_UPDATE to modify parameters of a subscription established
 * with PUBLISH"). */
static void moqtrun_ngr_pub(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, u64 v) {
  moqctl_params      params = {0};
  wired_moqtrun_req* q      = moqtrun_pub_req(hub, t);
  if (!moqtrun_ngr_due(moqtrun_ngr_st(q), t, v)) {
    return;
  }
  moqtrun_ngr_add(&params, v);
  if (moqtrun_pubupd_send(hub, q, &params)) {
    moqtrun_ngr_mark(&q->ngr, t, v);
  }
}

/* v to t's upstream: the hub's SUBSCRIBE stream, else the PUBLISH's. */
static void moqtrun_ngr_route(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, u64 v) {
  wired_moqtrun_up* u = moqtrun_up_of_track(hub, t);
  if (u) {
    moqtrun_ngr_try(hub, u, t, v);
    return;
  }
  moqtrun_ngr_pub(hub, t, v);
}

/* A downstream SUBSCRIBE or REQUEST_UPDATE (params) for Established t:
 * its NEW_GROUP_REQUEST goes upstream when due (MUST). */
void moqtrun_ngr_relay(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    const moqctl_params*       params) {
  u64 v;
  if (!t || !moqtrun_ngr_of(params, &v)) {
    return;
  }
  moqtrun_ngr_route(hub, t, v);
}
