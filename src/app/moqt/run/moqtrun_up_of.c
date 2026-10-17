#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_up_matches(const wired_moqtrun_up* u, moqtrun_key k);
static int moqtrun_up_on_stream(
    const wired_moqtrun_up* u, const wired_wt_session* s, u64 sid);
static int moqtrun_up_unanswered(
    const wired_moqtrun_up* u, const wired_wt_session* s);
static int moqtrun_up_is_track(const wired_moqtrun_track* t, u64 tag);

static int moqtrun_up_matches(const wired_moqtrun_up* u, moqtrun_key k) {
  return u->in_use && moqtrun_ns_eq(u->ns, u->ns_len, k.ns) &&
         moqtrun_ns_eq(u->name, u->name_len, k.name);
}

wired_moqtrun_up* moqtrun_up_of_key(wired_moqt_hub* hub, moqtrun_key k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++)
    if (moqtrun_up_matches(&hub->ups[i], k)) return &hub->ups[i];
  return 0;
}

wired_moqtrun_up* moqtrun_up_free_slot(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++)
    if (!hub->ups[i].in_use) return &hub->ups[i];
  return 0;
}

static int moqtrun_up_on_stream(
    const wired_moqtrun_up* u, const wired_wt_session* s, u64 sid) {
  return u->in_use && u->wt == s && u->stream_id == sid;
}

wired_moqtrun_up* moqtrun_up_of_stream(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++)
    if (moqtrun_up_on_stream(&hub->ups[i], s, sid)) return &hub->ups[i];
  return 0;
}

static int moqtrun_up_unanswered(
    const wired_moqtrun_up* u, const wired_wt_session* s) {
  return u->in_use && u->wt == s && !u->track_tag;
}

int moqtrun_up_pending_for(
    const wired_moqt_hub* hub, const wired_wt_session* s) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++)
    if (moqtrun_up_unanswered(&hub->ups[i], s)) return 1;
  return 0;
}

/* t is the live incarnation SUBSCRIBE_OK claimed (tag 0: none yet). */
static int moqtrun_up_is_track(const wired_moqtrun_track* t, u64 tag) {
  return tag && t->in_use && t->cache_tag == tag;
}

wired_moqtrun_track* moqtrun_up_track(
    wired_moqtrun_peer* pp, const wired_moqtrun_up* u) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; i++)
    if (moqtrun_up_is_track(&pp->tracks[i], u->track_tag))
      return &pp->tracks[i];
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
  u->ns_len     = k.ns.n;
  u->name_len   = k.name.n;
  u->in.n       = 0;
  u->in.at      = 0;
  u->in.skip    = 0;
  bytes_memcpy(u->ns, k.ns.p, k.ns.n);
  bytes_memcpy(u->name, k.name.p, k.name.n);
}
