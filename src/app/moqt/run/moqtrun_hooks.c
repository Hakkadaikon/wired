#include "app/moqt/run/moqtrun_impl.h"

/* The app-facing hooks beside the authorizers: session admission at the
 * client's SETUP, closing any session with a reason, and the read-only
 * Object tap. */

static const moqctl_token* moqtrun_setup_token(const moqctl_setup* m) {
  return m->has_auth_token ? &m->auth_token : 0;
}

static int moqtrun_peer_is_open(const wired_moqtrun_peer* p) {
  return p && !p->closing;
}

/* 1 iff the session publishing t (0 for none, or a scan of the hub's own
 * bytes with hub 0) is closing: what it sent is no longer cached, tapped
 * or relayed, even mid-delivery (wired_moqt_close in a hook). */
static const wired_moqtrun_peer* moqtrun_track_src(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  return hub && t ? moqtrun_track_peer(hub, t) : 0;
}

int moqtrun_track_closing(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  const wired_moqtrun_peer* p = moqtrun_track_src(hub, t);
  return p && p->closing;
}

static int moqtrun_peer_of_s(
    const wired_moqtrun_peer* p, const wired_wt_session* s) {
  return p->in_use && p->wt == s;
}

/* 1 iff s is a session of hub that is closing. */
static int moqtrun_sess_closing(
    const wired_moqt_hub* hub, const wired_wt_session* s) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    if (moqtrun_peer_of_s(&hub->peers[i], s)) {
      return hub->peers[i].closing;
    }
  }
  return 0;
}

/* An authorizer's verdict v for s: a grant from a hook that closed s
 * itself (wired_moqt_close) is a refusal, as with admit. */
int moqtrun_auth_grant(
    const wired_moqt_hub* hub, const wired_wt_session* s, int v) {
  return v && !moqtrun_sess_closing(hub, s);
}

/* s's peer while its session is open, else 0: nothing a closing session
 * sends is read any more (wired_moqt_on_stream_data, _on_datagram). */
wired_moqtrun_peer* moqtrun_open_peer(
    wired_moqt_hub* hub, wired_wt_session* s) {
  wired_moqtrun_peer* p = moqtrun_find_by_wt(hub, s);
  return moqtrun_peer_is_open(p) ? p : 0;
}

/* The admission verdict code: the hook may have closed p itself
 * (wired_moqt_close), which is a refusal too. 1 when refused. */
static int moqtrun_admit_close(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u32 code, wired_span reason) {
  if (p->closing) {
    return 1;
  }
  if (!code) {
    return 0;
  }
  moqtrun_close_with_r(hub, p, code, reason);
  return 1;
}

/* draft-22 9.1.4: the server judges the SETUP's AUTHORIZATION TOKEN
 * (hub->admit); a refusal closes p with the app's code and reason. 1
 * when refused. */
int moqtrun_admit_refused(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_setup* m) {
  wired_span reason = wired_span_of(0, 0);
  u32        code;
  if (!hub->admit) {
    return 0;
  }
  code = hub->admit(hub->admit_ctx, p->wt, moqtrun_setup_token(m), &reason);
  return moqtrun_admit_close(hub, p, code, reason);
}

int wired_moqt_close(
    wired_moqt_hub* hub, wired_wt_session* s, u32 code, wired_span reason) {
  wired_moqtrun_peer* p = moqtrun_open_peer(hub, s);
  return p ? moqtrun_close_with_r(hub, p, code, reason) : 0;
}

/* 0 hub: a scan of the hub's own bytes (wired_moqt_publish_blob). */
static int moqtrun_tap_set(const wired_moqt_hub* hub) {
  return hub && hub->tap;
}

/* The publisher of t while a tap is set, else 0: with no tap nothing can
 * close a publisher mid-delivery, so no peer is looked up per Object. */
static const wired_moqtrun_peer* moqtrun_tap_src(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  return moqtrun_tap_set(hub) && t ? moqtrun_track_peer(hub, t) : 0;
}

/* Field-wise prefix match on the encoded namespaces (moqtrun_disc_starts). */
static int moqtrun_tap_under(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  u64 n = 0;
  return moqtrun_disc_starts(
      moqtrun_disc_fields_of(hub->tap_prefix, &n),
      moqtrun_disc_fields_of(wired_span_of(t->ns, t->ns_len), &n));
}

/* o is to be tapped: a Normal Object within tap_max under tap_prefix. */
static int moqtrun_tap_due(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_track* t,
    const moqdata_obj*         o) {
  return o->status == MOQDATA_STATUS_NORMAL && o->payload.n <= hub->tap_max &&
         moqtrun_tap_under(hub, t);
}

/* Taps o when due; 1 when t's publisher is closing afterwards (the tap,
 * now or for an earlier Object of the delivery, called wired_moqt_close),
 * so o is neither noted, cached nor relayed. Always 0 with no tap set. */
int moqtrun_tap_obj(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_track* t,
    const moqdata_obj*         o) {
  const wired_moqtrun_peer* p = moqtrun_tap_src(hub, t);
  if (!moqtrun_peer_is_open(p)) {
    return p != 0;
  }
  if (moqtrun_tap_due(hub, t, o)) {
    hub->tap(
        hub->tap_ctx, p->wt, wired_span_of(t->ns, t->ns_len),
        wired_span_of(t->name, t->name_len), o->payload);
  }
  return p->closing;
}
