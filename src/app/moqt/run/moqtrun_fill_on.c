#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_fill_requested(
    const moqctl_param*        fp,
    const wired_moqtrun_sub*   sub,
    const wired_moqtrun_track* track);
static int moqtrun_fill_due(
    const wired_moqtrun_track* track,
    const wired_moqtrun_sub*   sub,
    const moqctl_param*        fp,
    moqfetch_fill*             fill,
    moqtrun_frange*            r);
static int  moqtrun_fill_bad(const moqctl_params* params);
static void moqtrun_fill_from_param(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* track,
    wired_moqtrun_sub*   sub,
    u64                  rid,
    const moqctl_param*  fp);
static int moqtrun_sub_has_rid(const wired_moqtrun_sub* s, usz idx, u64 rid);

/* A FILL_PARAMETERS parameter asks for a fill only while the
 * subscription forwards (SS9.20.15; FORWARD 0 holds everything), and
 * only of a live track -- state kept for a gone publisher has no cache. */
static int moqtrun_fill_requested(
    const moqctl_param*        fp,
    const wired_moqtrun_sub*   sub,
    const wired_moqtrun_track* track) {
  return fp != 0 && !sub->forward_off && track != 0;
}

/* 1 iff fp asks sub for a fill stream that opens: requested, decoded
 * into *fill, and its range (*r) not empty -- a range starting past the
 * Largest Object, or an empty track, opens nothing; an end past it is
 * cut to it (SS3.4). */
static int moqtrun_fill_due(
    const wired_moqtrun_track* track,
    const wired_moqtrun_sub*   sub,
    const moqctl_param*        fp,
    moqfetch_fill*             fill,
    moqtrun_frange*            r) {
  moqctl_rangeloc rl;
  if (!moqtrun_fill_requested(fp, sub, track)) return 0;
  if (moqfetch_fill_take(fp->bytes, fill) != MOQCTL_OK) return 0;
  rl = moqtrun_fill_rl(fill, sub);
  return moqtrun_fetch_resolve(track, &rl, r);
}

/* 1 unless params' fill is due and both fetches[] and fetch_waits[] are
 * full. SS3.4.1 lets no accepted fill go unopened and unreset, so this
 * is decided before the SUBSCRIBE_OK/REQUEST_OK: such a request is
 * refused REQUEST_ERROR instead. */
int moqtrun_fill_room(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* track,
    const wired_moqtrun_sub*   sub,
    const moqctl_params*       params) {
  moqfetch_fill       fill;
  moqtrun_frange      r;
  const moqctl_param* fp =
      moqctl_params_find(params, MOQCTL_PARAM_FILL_PARAMETERS);
  return !moqtrun_fill_due(track, sub, fp, &fill, &r) ||
         moqtrun_fetch_arr_slot(hub->fetches) ||
         moqtrun_fetch_arr_slot(hub->fetch_waits);
}

/* 1 iff params carries a FILL_PARAMETERS whose value does not decode. */
static int moqtrun_fill_bad(const moqctl_params* params) {
  const moqctl_param* fp =
      moqctl_params_find(params, MOQCTL_PARAM_FILL_PARAMETERS);
  moqfetch_fill fill;
  return fp != 0 && moqfetch_fill_take(fp->bytes, &fill) != MOQCTL_OK;
}

/* A malformed FILL_PARAMETERS (an unknown or truncated inner Parameter)
 * closes the session with PROTOCOL_VIOLATION (SS9.20.15 with SS9.20),
 * checked before the SUBSCRIBE or REQUEST_UPDATE is answered. 1 when
 * closed. */
int moqtrun_fill_malformed(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_params* params) {
  if (!moqtrun_fill_bad(params)) return 0;
  moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
  return 1;
}

/* Opens fp's fill under rid when it is due (moqtrun_fill_due). */
static void moqtrun_fill_from_param(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* track,
    wired_moqtrun_sub*   sub,
    u64                  rid,
    const moqctl_param*  fp) {
  moqfetch_fill  fill;
  moqtrun_frange r;
  if (!moqtrun_fill_due(track, sub, fp, &fill, &r)) return;
  moqtrun_fill_open(hub, p, sub, rid, &fill, &r);
}

/* FILL_PARAMETERS on an accepted SUBSCRIBE: the fill rides the
 * SUBSCRIBE's own Request ID. */
void moqtrun_fill_on_subscribe(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* track,
    wired_moqtrun_sub*   sub,
    const moqctl_params* params) {
  moqtrun_fill_from_param(
      hub, p, track, sub, sub->request_id,
      moqctl_params_find(params, MOQCTL_PARAM_FILL_PARAMETERS));
}

/* FILL_PARAMETERS on an applied REQUEST_UPDATE: the new fill's
 * FETCH_HEADER carries the update's own Request ID (draft-22 9.8), an
 * earlier fill keeps running beside it. Only a live track is filled
 * (moqtrun_fill_requested). */
void moqtrun_fill_on_update(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* track,
    wired_moqtrun_sub*   sub,
    const moqctl_params* params,
    u64                  rid) {
  moqtrun_fill_from_param(
      hub, p, track, sub, rid,
      moqctl_params_find(params, MOQCTL_PARAM_FILL_PARAMETERS));
}

static int moqtrun_sub_has_rid(const wired_moqtrun_sub* s, usz idx, u64 rid) {
  return moqtrun_sub_is_peer(s, idx) && s->request_id == rid;
}

wired_moqtrun_sub* moqtrun_track_sub_by_rid(
    wired_moqtrun_track* t, usz idx, u64 rid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (moqtrun_sub_has_rid(&t->subs[i], idx, rid)) return &t->subs[i];
  return 0;
}
