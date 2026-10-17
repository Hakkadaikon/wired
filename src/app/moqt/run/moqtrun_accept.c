#include "app/moqt/run/moqtrun_impl.h"

static u64 moqtrun_accept_code(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* track,
    wired_moqtrun_sub*         slot,
    const moqctl_params*       params);

void moqtrun_largest_param(
    moqctl_params* params, const wired_moqtrun_track* t) {
  const moqctl_loc* top = moqtrun_track_top(t);
  params->items[0].type = MOQCTL_PARAM_LARGEST_OBJECT;
  params->items[0].enc  = MOQCTL_PENC_LOCATION;
  params->n             = top != 0;
  if (top) params->items[0].loc = *top;
}

/* SUBSCRIBE_OK with s's alias; LARGEST_OBJECT once t has published
 * Objects (MUST, draft 10.2.16); t's Track Properties unless s asked
 * INCLUDE_PROPERTIES=0 (draft-22 9.20.21). */
void moqtrun_queue_subscribe_ok(
    wired_moqtrun_peer*        p,
    const wired_moqtrun_track* t,
    const wired_moqtrun_sub*   s) {
  u8                  msg[WIRED_MOQTRUN_CTL_REPLY_MAX];
  moqctl_subscribe_ok ok = {0};
  ok.track_alias         = s->track_alias;
  ok.track_properties = wired_span_of(t->props, s->no_props ? 0 : t->props_len);
  moqtrun_largest_param(&ok.params, t);
  usz n = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_SUBSCRIBE_OK,
      moqtrun_encode_subscribe_ok, &ok);
  moqtrun_queue_reply(p, wired_span_of(msg, n));
  moqtrun_req_mark_live(p);
}

/* The accepted SUBSCRIBE's refusal, decided before SUBSCRIBE_OK: a fill no
 * table can hold, or a SWITCHING_SET_ASSIGNMENT the session cannot take
 * (SSTS, moqtssts_run.c); MOQTRUN_REQ_ACCEPT otherwise (joined). */
static u64 moqtrun_accept_code(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* track,
    wired_moqtrun_sub*         slot,
    const moqctl_params*       params) {
  if (!moqtrun_fill_room(hub, track, slot, params))
    return MOQCTL_ERR_INTERNAL_ERROR;
  return moqtss_on_subscribe(hub, slot, params, track);
}

/* Records slot (peer_idx, its session's alias for track) against track,
 * replies SUBSCRIBE_OK with that alias, opens any requested fill and
 * notes name k for re-attach. A fill no table can hold refuses the
 * SUBSCRIBE first (draft-22 SS3.4.1: no fill accepted, then lost). */
void moqtrun_accept_subscribe(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    wired_moqtrun_track*    track,
    wired_moqtrun_sub*      slot,
    usz                     peer_idx,
    const moqctl_subscribe* m,
    moqtrun_key             k) {
  moqtrun_sub_open(
      slot, track, peer_idx, moqtrun_session_alias(hub, peer_idx, track), m);
  u64 code = moqtrun_accept_code(hub, track, slot, &m->params);
  if (code != MOQTRUN_REQ_ACCEPT) {
    slot->active = 0;
    moqtrun_send_request_error(p, code);
    return;
  }
  moqtrun_queue_subscribe_ok(p, track, slot);
  /* SWITCH_FROM (moqtswitch.c) */
  moqtsw_begin(hub, moqtrun_sw_ops(), track, slot, &m->params);
  moqtrun_fill_on_subscribe(hub, p, track, slot, &m->params);
  moqtrun_note_sub_name(p, k, slot);
}

/* A peer's first SUBSCRIBE for the hub's blob: one io.send_uni with the
 * whole framed bytes, and only an accepted send records the subscription
 * (a refused one answers REQUEST_ERROR, so the peer's next SUBSCRIBE tries
 * again). Unlike a peer track's per-subscriber alias, SUBSCRIBE_OK carries
 * the blob's own alias -- the one its framed header has -- so the
 * subscriber can bind the stream to this subscription. */
/* Sends the blob to slot's peer p unless FORWARD 0 holds it back; 0 when
 * the send is refused. */
int moqtrun_blob_deliver(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_sub* slot) {
  if (!moqtrun_sub_forwards(slot)) return 1;
  slot->blob_sent = hub->io.send_uni(p->wt, hub->blob_wire) >= 0;
  hub->stat_open_drop += !slot->blob_sent;
  slot->stream_count += slot->blob_sent;
  return slot->blob_sent;
}

void moqtrun_blob_send_first(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m) {
  wired_moqtrun_sub* slot = moqtrun_sub_slot(&hub->blob_track);
  if (!slot) {
    moqtrun_send_request_error(p, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  moqtrun_sub_open(
      slot, &hub->blob_track, peer_idx, hub->blob_track.own_alias, m);
  if (!moqtrun_blob_deliver(hub, p, slot)) {
    slot->active = 0;
    moqtrun_send_request_error(p, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  moqtrun_queue_subscribe_ok(p, &hub->blob_track, slot);
}
