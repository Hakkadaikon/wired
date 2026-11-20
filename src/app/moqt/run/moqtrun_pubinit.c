#include "app/moqt/run/moqtrun_impl.h"

/* The PUBLISH's initial subscription parameters (draft-22/23 9.8) as
 * track-level state, and the clamp feeding them into each downstream
 * subscription's resolve -- split out of moqtrun_param.c to keep that
 * file at the Halstead volume gate. */

static void moqtrun_sub_clamp_start(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t);
static int moqtrun_pub_end_tighter(
    const wired_moqtrun_sub* s, const wired_moqtrun_track* t);
static void moqtrun_sub_clamp_end(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t);
static void moqtrun_track_pub_filter(
    wired_moqtrun_track* t, const moqctl_param* f);
static void moqtrun_subs_pub_refresh(wired_moqtrun_track* t);

static void moqtrun_sub_clamp_start(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t) {
  if (moqctl_loc_less(s->start, t->pub_start)) {
    s->start = t->pub_start;
  }
}

/* The PUBLISH filter's last Group ends before s's own. */
static int moqtrun_pub_end_tighter(
    const wired_moqtrun_sub* s, const wired_moqtrun_track* t) {
  return t->pub_has_end_group &&
         (!s->has_end_group || t->pub_end_group < s->end_group);
}

/* shortcut: with equal last Groups the subscription's End Object stands
 * even when the PUBLISH's is smaller; intersect per Object if publishers
 * send such filters. */
static void moqtrun_sub_clamp_end(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t) {
  if (!moqtrun_pub_end_tighter(s, t)) {
    return;
  }
  s->has_end_group  = 1;
  s->end_group      = t->pub_end_group;
  s->has_end_object = t->pub_has_end_object;
  s->end_object     = t->pub_end_object;
}

/* draft-22/23 9.8: the PUBLISH's initial LOCATION_FILTER bounds every
 * subscription of the track, filtered or not. */
void moqtrun_sub_clamp_pub(wired_moqtrun_sub* s, const wired_moqtrun_track* t) {
  if (!t || !t->pub_has_filter) {
    return;
  }
  moqtrun_sub_clamp_start(s, t);
  moqtrun_sub_clamp_end(s, t);
}

/* The PUBLISH's LOCATION_FILTER f, resolved against t's Largest (claim
 * zeroed pub_has_filter, so the resolve is unclamped), kept as the
 * track's bound for every subscription (moqtrun_sub_resolve). */
static void moqtrun_track_pub_filter(
    wired_moqtrun_track* t, const moqctl_param* f) {
  wired_moqtrun_sub s = {0};
  moqtrun_sub_filter(&s, t, f);
  t->pub_has_filter     = s.has_filter;
  t->pub_start          = s.start;
  t->pub_has_end_group  = s.has_end_group;
  t->pub_end_group      = s.end_group;
  t->pub_has_end_object = s.has_end_object;
  t->pub_end_object     = s.end_object;
}

/* draft-22/23 9.8 (caps-gated: earlier drafts' PUBLISH has no such
 * text): the PUBLISH parameters governing delivery "inform the
 * Subscriber of the initial Subscription parameters"; kept on the track
 * and fed to the gates SUBSCRIBE parameters reach (moqtrun_sub_resolve,
 * moqtrun_sub_pub_defaults). Called from the PUBLISH path only: 9.8
 * scopes the initial state to PUBLISH, so an upstream SUBSCRIBE_OK
 * (moqtrun_up_claim) sets none. FORWARD/PAUSED is pub_paused;
 * SUBSCRIBER_PRIORITY is not taken over (moqtrun_sub_pub_defaults'
 * doc); EXPIRES is advisory (9.20.16: the sender terminates), so
 * nothing is kept for it. */
void moqtrun_track_pub_params(
    wired_moqtrun_track* t, u64 caps, const moqctl_params* params) {
  if (!(caps & MOQVER_CAP_PUB_INIT_PARAMS)) {
    /* claim left pub_* zeroed: no initial state. 9.8 is draft-22/23
     * text only, so an earlier draft's re-PUBLISH also leaves surviving
     * subscriptions' resolved filters alone. */
    return;
  }
  t->pub_group_order =
      moqtrun_param_u8(moqctl_params_find(params, MOQCTL_PARAM_GROUP_ORDER));
  t->pub_delivery_ms = moqtrun_param_vi(
      moqctl_params_find(params, MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT));
  moqtrun_track_pub_filter(
      t, moqctl_params_find(params, MOQCTL_PARAM_LOCATION_FILTER));
  moqtrun_subs_pub_refresh(t);
}

/* A re-PUBLISH on a live slot keeps its subscriptions
 * (moqtrun_track_claim clears subs only on a fresh claim): the new
 * incarnation's 9.8 initial state replaces the old one's for each,
 * re-resolved like a re-attach -- the stored Locations name the old
 * incarnation's Objects (moqtrun_sub_reresolve's doc). The re-resolve
 * re-derives start/end, so the SWITCH_FROM bound is re-applied after it,
 * as every re-resolving path does (moqtrun_update.c, moqtsw_reattached)
 * -- not moqtsw_reattached itself: the slot stayed live, so no orphan
 * sweep or sw_live count is due. */
static void moqtrun_subs_pub_refresh(wired_moqtrun_track* t) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    if (t->subs[i].active) {
      moqtrun_sub_pub_defaults(&t->subs[i], t);
      moqtrun_sub_reresolve(&t->subs[i], t);
      moqtsw_rebound(&t->subs[i]);
    }
  }
}
