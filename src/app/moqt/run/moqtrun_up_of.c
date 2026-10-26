#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_up_on_stream(
    const wired_moqtrun_up* u, const wired_wt_session* s, u64 sid);
static int moqtrun_up_unanswered(
    const wired_moqtrun_up* u, const wired_wt_session* s);
static int moqtrun_up_is_track(const wired_moqtrun_track* t, u64 tag);
static int moqtrun_up_crossing(
    const wired_moqtrun_peer* p, const wired_moqtrun_up* u);

int moqtrun_up_matches(const wired_moqtrun_up* u, moqtrun_key k) {
  return u->in_use && moqtrun_ns_eq(u->ns, u->ns_len, k.ns) &&
         moqtrun_ns_eq(u->name, u->name_len, k.name);
}

wired_moqtrun_up* moqtrun_up_of_key(wired_moqt_hub* hub, moqtrun_key k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++) {
    if (moqtrun_up_matches(&hub->ups[i], k)) {
      return &hub->ups[i];
    }
  }
  return 0;
}

wired_moqtrun_up* moqtrun_up_free_slot(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++) {
    if (!hub->ups[i].in_use) {
      return &hub->ups[i];
    }
  }
  return 0;
}

static int moqtrun_up_on_stream(
    const wired_moqtrun_up* u, const wired_wt_session* s, u64 sid) {
  return u->in_use && u->wt == s && u->stream_id == sid;
}

wired_moqtrun_up* moqtrun_up_of_stream(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++) {
    if (moqtrun_up_on_stream(&hub->ups[i], s, sid)) {
      return &hub->ups[i];
    }
  }
  return 0;
}

/* u is in use toward s. */
static int moqtrun_up_on_wt(
    const wired_moqtrun_up* u, const wired_wt_session* s) {
  return u->in_use && u->wt == s;
}

/* Pending: not answered yet (a refusal record is answered). */
static int moqtrun_up_unanswered(
    const wired_moqtrun_up* u, const wired_wt_session* s) {
  return moqtrun_up_on_wt(u, s) && !u->track_tag && !u->failed;
}

/* u is s's entry for k. */
int moqtrun_up_matches_wt(
    const wired_moqtrun_up* u, moqtrun_key k, const wired_wt_session* s) {
  return u->wt == s && moqtrun_up_matches(u, k);
}

/* The entry for k toward s (one per publisher, moqtrun_up_fan.c), else 0. */
wired_moqtrun_up* moqtrun_up_of_key_wt(
    wired_moqt_hub* hub, moqtrun_key k, const wired_wt_session* s) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++) {
    if (moqtrun_up_matches_wt(&hub->ups[i], k, s)) {
      return &hub->ups[i];
    }
  }
  return 0;
}

/* draft-18 5.1: p's PUBLISH crosses u, the hub's own SUBSCRIBE to p for
 * the same Track still Pending (subscriber). */
static int moqtrun_up_crossing(
    const wired_moqtrun_peer* p, const wired_moqtrun_up* u) {
  return (moqver_caps(p->ver) & MOQVER_CAP_DUP_SUBSCRIPTION) && u &&
         moqtrun_up_unanswered(u, p->wt);
}

/* The crossed SUBSCRIBE is cancelled -- Terminated -- before the
 * PUBLISH_OK goes out (MUST); its waiters already took p's track. */
void moqtrun_up_crossed(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, moqtrun_key k) {
  wired_moqtrun_up* u = moqtrun_up_of_key_wt(hub, k, p->wt);
  if (!moqtrun_up_crossing(p, u)) {
    return;
  }
  moqtrun_up_reset(hub, p, u);
  u->in_use = 0;
}

int moqtrun_up_pending_for(
    const wired_moqt_hub* hub, const wired_wt_session* s) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++) {
    if (moqtrun_up_unanswered(&hub->ups[i], s)) {
      return 1;
    }
  }
  return 0;
}

/* t is the live incarnation SUBSCRIBE_OK claimed (tag 0: none yet). */
static int moqtrun_up_is_track(const wired_moqtrun_track* t, u64 tag) {
  return tag && t->in_use && t->cache_tag == tag;
}

wired_moqtrun_track* moqtrun_up_track(
    wired_moqtrun_peer* pp, const wired_moqtrun_up* u) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; i++) {
    if (moqtrun_up_is_track(&pp->tracks[i], u->track_tag)) {
      return &pp->tracks[i];
    }
  }
  return 0;
}

/* ----- sending the SUBSCRIBE ----- */

int moqtrun_up_encode_sub(wired_mspan buf, usz* off, const void* m) {
  return moqctl_subscribe_encode(buf, off, m);
}

void moqtrun_up_store(
    wired_moqtrun_up* u, wired_wt_session* s, u64 sid, u64 rid, moqtrun_key k) {
  u->in_use     = 1;
  u->wt         = s;
  u->stream_id  = sid;
  u->request_id = rid;
  u->track_tag  = 0;
  u->done       = 0;
  u->ngr.out    = 0;
  u->upd_out    = 0;
  u->failed     = 0;
  moqsub_init(&u->sub, MOQSUB_ROLE_SUBSCRIBER);
  moqsub_step(&u->sub, MOQSUB_EV_OPEN);
  u->ns_len   = k.ns.n;
  u->name_len = k.name.n;
  u->in.n     = 0;
  u->in.at    = 0;
  u->in.skip  = 0;
  bytes_memcpy(u->ns, k.ns.p, k.ns.n);
  bytes_memcpy(u->name, k.name.p, k.name.n);
}
