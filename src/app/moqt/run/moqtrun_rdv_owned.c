#include "app/moqt/run/moqtrun_impl.h"

static usz moqtrun_rdv_count(
    const wired_moqt_hub* hub, const wired_wt_session* s);
static u64  moqtrun_rdv_deadline(const wired_moqt_hub* hub, u64 rt);
static void moqtrun_rdv_store(
    wired_moqt_hub*           hub,
    wired_moqtrun_rdv*        r,
    const wired_moqtrun_peer* p,
    moqtrun_key               k,
    wired_span                body,
    u64                       rt);
static int                moqtrun_rdv_fits(wired_span body, int room);
static wired_moqtrun_rdv* moqtrun_rdv_take(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_span body, int room);
static const wired_wt_session* moqtrun_rdv_pub_of(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t);
static int moqtrun_rdv_on_pub(
    const wired_moqtrun_rdv* r, const wired_wt_session* pub);
static int moqtrun_rdv_pub_room(
    const wired_moqt_hub* hub, const wired_wt_session* pub);
static void moqtrun_rdv_hold(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    const moqctl_subscribe* m,
    moqtrun_key             k,
    wired_span              body);

int moqtrun_rdv_owned(const wired_moqtrun_rdv* r, const wired_wt_session* s) {
  return r->in_use && r->wt == s;
}

static usz moqtrun_rdv_count(
    const wired_moqt_hub* hub, const wired_wt_session* s) {
  usz n = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++) {
    n += (usz)moqtrun_rdv_owned(&hub->rdv[i], s);
  }
  return n;
}

/* A free slot for s, unless s holds its share or the table is full. */
wired_moqtrun_rdv* moqtrun_rdv_admit(
    wired_moqt_hub* hub, const wired_wt_session* s) {
  return moqtrun_rdv_count(hub, s) < WIRED_MOQTRUN_RDV_PER_SESSION
             ? moqtrun_rdv_free_slot(hub)
             : 0;
}

/* The deadline, clamped to WIRED_MOQTRUN_RDV_MAX_MS (10.2.6: the relay
 * MAY use a shorter one); WIRED_MOQTRUN_UP_WAIT_MS for a hold with none
 * (rt 0), so a silent upstream cannot keep it forever. */
static u64 moqtrun_rdv_deadline(const wired_moqt_hub* hub, u64 rt) {
  return hub->live.last_now_ms + (rt ? u64_min(rt, WIRED_MOQTRUN_RDV_MAX_MS)
                                     : WIRED_MOQTRUN_UP_WAIT_MS);
}

/* Fills r from p's request. */
static void moqtrun_rdv_store(
    wired_moqt_hub*           hub,
    wired_moqtrun_rdv*        r,
    const wired_moqtrun_peer* p,
    moqtrun_key               k,
    wired_span                body,
    u64                       rt) {
  r->in_use      = 1;
  r->wt          = p->wt;
  r->stream_id   = p->req->stream_id;
  r->deadline_ms = moqtrun_rdv_deadline(hub, rt);
  r->up_only     = rt == 0;
  r->repath      = 0;
  r->resume      = 0;
  r->tried       = 0;
  r->ns_len      = k.ns.n;
  r->name_len    = k.name.n;
  r->body_len    = body.n;
  bytes_memcpy(r->ns, k.ns.p, k.ns.n);
  bytes_memcpy(r->name, k.name.p, k.name.n);
  bytes_memcpy(r->body, body.p, body.n);
}

static int moqtrun_rdv_fits(wired_span body, int room) {
  return room && body.n <= WIRED_MOQTRUN_CTL_MSG_MAX;
}

/* A slot for p's request body; with no slot left (room 0 included) -- or
 * a body longer than a slot keeps (WIRED_MOQTRUN_CTL_MSG_MAX; up to 65535
 * bytes arrive) -- it is refused EXCESSIVE_LOAD with a Retry Interval at
 * once (10.6), never dropped silently, and 0 returned. */
static wired_moqtrun_rdv* moqtrun_rdv_take(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_span body, int room) {
  wired_moqtrun_rdv* r =
      moqtrun_rdv_fits(body, room) ? moqtrun_rdv_admit(hub, p->wt) : 0;
  if (!r) {
    moqtrun_send_request_error_ri(
        p, MOQCTL_ERR_EXCESSIVE_LOAD, WIRED_MOQTRUN_RDV_RETRY);
  }
  return r;
}

/* Holds the SUBSCRIBE, sending nothing yet (moqtrun_rdv_take). */
static void moqtrun_rdv_hold(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    const moqctl_subscribe* m,
    moqtrun_key             k,
    wired_span              body) {
  wired_moqtrun_rdv* r = moqtrun_rdv_take(hub, p, body, 1);
  if (!r) {
    return;
  }
  moqtrun_rdv_store(hub, r, p, k, body, moqtrun_rdv_rt(m));
  r->has_ngr       = moqtrun_ngr_of(&m->params, &r->ngr);
  p->req->rdv_held = 1;
}

static const wired_wt_session* moqtrun_rdv_pub_of(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  const wired_moqtrun_peer* pp = moqtrun_track_peer(hub, t);
  return pp ? pp->wt : 0;
}

static int moqtrun_rdv_on_pub(
    const wired_moqtrun_rdv* r, const wired_wt_session* pub) {
  return r->in_use && r->resume && r->pub_wt == pub;
}

/* pub's PUBLISHes hold fewer than half of the slots, so one silent
 * publisher cannot starve every other track's waits. */
static int moqtrun_rdv_pub_room(
    const wired_moqt_hub* hub, const wired_wt_session* pub) {
  usz n = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++) {
    n += (usz)moqtrun_rdv_on_pub(&hub->rdv[i], pub);
  }
  return n < WIRED_MOQTRUN_MAX_RDV / 2;
}

/* Holds p's SUBSCRIBE or TRACK_STATUS (body) until t's PUBLISH is
 * unpaused (draft-23 7.5, moqtrun_resume_wait), WIRED_MOQTRUN_UP_WAIT_MS at
 * most. The slot, or 0 when refused (moqtrun_rdv_take; also when t's
 * publisher already holds half of the slots). */
wired_moqtrun_rdv* moqtrun_rdv_wait(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    const wired_moqtrun_track* t,
    wired_span                 body) {
  const wired_wt_session* pub = moqtrun_rdv_pub_of(hub, t);
  wired_moqtrun_rdv*      r =
      moqtrun_rdv_take(hub, p, body, moqtrun_rdv_pub_room(hub, pub));
  if (!r) {
    return 0;
  }
  moqtrun_rdv_store(hub, r, p, moqtrun_track_key(t), body, 0);
  r->has_ngr       = 0;
  r->resume        = 1;
  r->pub_wt        = pub;
  p->req->rdv_held = 1;
  return r;
}

/* A SUBSCRIBE whose track has no publisher: held (moqtrun_rdv_holdable),
 * else DOES_NOT_EXIST at once (10.2.6: 0 or absent MUST). */
void moqtrun_rdv_miss(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    const moqctl_subscribe* m,
    moqtrun_key             k,
    wired_span              body) {
  if (!moqtrun_rdv_holdable(hub, p, m, k)) {
    moqtrun_send_request_error(p, MOQCTL_ERR_DOES_NOT_EXIST);
    return;
  }
  moqtrun_rdv_hold(hub, p, m, k, body);
}

/* 1 iff r holds a SUBSCRIBE for exactly k (draft 1.5 Full Track Name). */
int moqtrun_rdv_matches(const wired_moqtrun_rdv* r, moqtrun_key k) {
  return r->in_use && moqtrun_ns_eq(r->ns, r->ns_len, k.ns) &&
         moqtrun_ns_eq(r->name, r->name_len, k.name);
}

int moqtrun_rdv_peer_open(const wired_moqtrun_peer* sp) {
  return sp && !sp->closing;
}

/* r's request slot (*sp its session), else 0: the session or the stream
 * is gone, or the hub is closing the session (nothing more goes to it). */
wired_moqtrun_req* moqtrun_rdv_target(
    wired_moqt_hub* hub, const wired_moqtrun_rdv* r, wired_moqtrun_peer** sp) {
  *sp = moqtrun_find_by_wt(hub, r->wt);
  return moqtrun_rdv_peer_open(*sp) ? moqtrun_req_find(hub, r->wt, r->stream_id)
                                    : 0;
}
