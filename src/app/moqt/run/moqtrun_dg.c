#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_dg_prop_violates(
    const wired_moqtrun_peer* p, const moqdg_obj* o);
static wired_moqtrun_track* moqtrun_dg_track(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_span          data,
    moqctl_loc*         loc);
static void moqtrun_dg_to_one(
    wired_moqt_hub* hub, const wired_moqtrun_sub* sub, wired_span data);
static void moqtrun_dg_fanout(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* track,
    wired_span                 data,
    moqctl_loc                 loc);
static void moqtrun_sw_sweep(wired_moqt_hub* hub);
static void moqtrun_rel_clear_sub(
    wired_moqt_hub* hub, const wired_moqtrun_relay* r, usz si);

/* draft-18 (ruling Q18-05): a delivery-timeout Object Property on a
 * datagram is undefined input, closed PROTOCOL_VIOLATION. */
static int moqtrun_dg_prop_violates(
    const wired_moqtrun_peer* p, const moqdg_obj* o) {
  return (moqver_caps(p->ver) & MOQVER_CAP_DG_TIMEOUT_PROP_CLOSE) &&
         moqtrun_props_have_timeout(o->props);
}

/* Resolves one received OBJECT_DATAGRAM to the sending peer's track:
 * decode via moqdg_take (11.3.1), then the header's Track Alias via
 * moqtrun_track_by_alias. 0 when the datagram is malformed or the alias
 * matches none of p's tracks -- the caller drops it whole -- or when it
 * closed the session (moqtrun_dg_prop_violates). */
static wired_moqtrun_track* moqtrun_dg_track(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_span          data,
    moqctl_loc*         loc) {
  usz       off = 0;
  moqdg_obj obj;
  if (moqdg_take(data, &off, &obj) != MOQDATA_OK) return 0;
  if (moqtrun_dg_prop_violates(p, &obj)) {
    moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
    return 0;
  }
  wired_moqtrun_track* t = moqtrun_track_by_alias(p, obj.track_alias);
  moqtrun_track_note(t, obj.group_id, obj.object_id);
  *loc = moqctl_loc_of(obj.group_id, obj.object_id);
  return t;
}

/* One subscriber's copy: the same bytes, only the Track Alias re-spelled
 * to the subscriber's own (moqtrun_alias_splice; usually a no-op). An
 * accepted queue counts on stat_dg_sent, a refusal on
 * stat_dg_drop -- and that copy is simply gone (no retransmission, no
 * busy streak: the next audio frame arrives in ~20ms anyway). */
static void moqtrun_dg_to_one(
    wired_moqt_hub* hub, const wired_moqtrun_sub* sub, wired_span data) {
  wired_moqtrun_peer* dst = &hub->peers[sub->session_idx];
  if (!dst->in_use) return;
  wired_span out = moqtrun_alias_splice(hub, data, sub->track_alias);
  if (hub->io.send_datagram(dst->wt, out) == 1)
    hub->stat_dg_sent++;
  else
    hub->stat_dg_drop++;
}

/* Stateless fan-out to every active subscriber of the track whose
 * Location Filter takes the Object at loc -- the datagram twin of
 * moqtrun_relay_object. A deactivated (closed) subscription is skipped;
 * late subscribers get nothing retroactively. Sent the moment it arrives,
 * a datagram is never past an OBJECT_DELIVERY_TIMEOUT (draft 8). */
static void moqtrun_dg_fanout(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* track,
    wired_span                 data,
    moqctl_loc                 loc) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (moqtrun_sub_gets_loc(&track->subs[i], loc))
      moqtrun_dg_to_one(hub, &track->subs[i], data);
}

/* SWITCH_FROM (moqtswitch.c): ends the switches now due, their
 * PUBLISH_DONEs flushed. */
static void moqtrun_sw_sweep(wired_moqt_hub* hub) {
  if (moqtsw_step(hub, moqtrun_sw_ops())) moqtrun_reqs_tick(hub);
}

void wired_moqt_on_datagram(
    void* app_ctx, wired_wt_session* s, wired_span data) {
  wired_moqt_hub*     hub = (wired_moqt_hub*)app_ctx;
  wired_moqtrun_peer* p   = moqtrun_find_by_wt(hub, s);
  if (!moqtrun_dg_ready(hub, p)) return;
  moqctl_loc           loc   = {0, 0};
  wired_moqtrun_track* track = moqtrun_dg_track(hub, p, data, &loc);
  /* Malformed or unknown-alias: dropped whole. Draft 11.3.1 says an
   * invalid Type MUST close the session (PROTOCOL_VIOLATION), but this
   * hub's io table has no close operation -- counting is the closest. */
  if (!track) {
    hub->stat_dg_bad++;
    return;
  }
  moqtss_prime(hub, track, loc.group); /* SSTS (moqtssts_run.c) */
  moqtrun_dg_fanout(hub, track, data, loc);
  moqtrun_sw_sweep(hub); /* SWITCH_FROM: a datagram of B's G cuts Hard */
}

/* A ring-backed relay also deactivates the dead subscriber's ring
 * cursor, so the next drain reclaims past it (and can release a
 * publisher hold the leaver's backlog was causing). */
static void moqtrun_rel_clear_sub(
    wired_moqt_hub* hub, const wired_moqtrun_relay* r, usz si) {
  if (r->in_use && r->rel_idx >= 0)
    hub->rel_pool[r->rel_idx].subs[si].active = 0;
}

/* Clear every relay's record of subscriber slot si's stream, so a later
 * relay round neither appends to nor late-opens a stream on the dead
 * session. */
void moqtrun_relays_clear_sub(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz si) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++) {
    t->relays[r].sub_stream_set[si] = 0;
    moqtrun_rel_clear_sub(hub, &t->relays[r], si);
  }
}

/* sub is held by peer index idx under Request ID rid (or any rid). */
int moqtrun_sub_is_req(const wired_moqtrun_sub* sub, usz idx, u64 rid) {
  return moqtrun_sub_is_peer(sub, idx) &&
         (rid == MOQTRUN_RID_ANY || sub->request_id == rid);
}
