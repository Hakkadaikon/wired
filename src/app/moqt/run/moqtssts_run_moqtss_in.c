#include "app/moqt/run/moqtssts_run_impl.h"

static int moqtss_sub_is(const wired_moqtrun_sub* s, usz sidx, u64 alias);
static u64 moqtss_open_of(const wired_moqtrun_track* t, usz i);
static int moqtss_in_subs(
    const wired_moqtrun_track* t, usz sidx, u64 alias, u64* open);
static int moqtss_on_track(
    const wired_moqtrun_track* t, usz sidx, u64 alias, u64* open);
static int moqtss_in_tracks(
    const wired_moqtrun_peer* p, usz sidx, u64 alias, u64* open);
static int moqtss_on_peer(
    const wired_moqtrun_peer* p, usz sidx, u64 alias, u64* open);

/* Set properties: the most recently received assignment wins. */
void moqtss_set_props(moqtss_set* st, const moqctl_ssa* a) {
  st->algorithm_id = a->algorithm_id;
  st->weight       = a->weight;
  st->activate     = a->activate;
  st->rank         = a->rank;
}

/* ===== subscriptions behind the members ===== */

static int moqtss_sub_is(const wired_moqtrun_sub* s, usz sidx, u64 alias) {
  return s->active && s->session_idx == sidx && s->track_alias == alias;
}

/* Open subscriber streams of track's sub slot i (relays carrying it). */
static u64 moqtss_open_of(const wired_moqtrun_track* t, usz i) {
  u64 n = 0;
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++)
    n += (u64)(t->relays[r].in_use && t->relays[r].sub_stream_set[i]);
  return n;
}

static int moqtss_in_subs(
    const wired_moqtrun_track* t, usz sidx, u64 alias, u64* open) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (moqtss_sub_is(&t->subs[i], sidx, alias)) {
      *open = moqtss_open_of(t, i);
      return 1;
    }
  return 0;
}

static int moqtss_on_track(
    const wired_moqtrun_track* t, usz sidx, u64 alias, u64* open) {
  return t->in_use && moqtss_in_subs(t, sidx, alias, open);
}

static int moqtss_in_tracks(
    const wired_moqtrun_peer* p, usz sidx, u64 alias, u64* open) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    if (moqtss_on_track(&p->tracks[t], sidx, alias, open)) return 1;
  return 0;
}

static int moqtss_on_peer(
    const wired_moqtrun_peer* p, usz sidx, u64 alias, u64* open) {
  return p->in_use && moqtss_in_tracks(p, sidx, alias, open);
}

/* 1 iff session sidx still holds an active subscription under alias;
 * its open stream count in *open. */
int moqtss_live(const wired_moqt_hub* hub, usz sidx, u64 alias, u64* open) {
  *open = 0;
  for (usz p = 0; p < WIRED_MOQTRUN_MAX_SESSIONS; p++)
    if (moqtss_on_peer(&hub->peers[p], sidx, alias, open)) return 1;
  return 0;
}

/* Drops slot k's members whose subscription is gone; the set itself once
 * empty (switching_set.rs remove). */
void moqtss_prune_set(
    const wired_moqt_hub* hub, moqtss_sess* ss, usz sidx, usz k) {
  moqtss_set* st = &ss->sets[k];
  u64         open;
  for (usz i = st->n; i > 0; i--)
    if (!moqtss_live(hub, sidx, st->m[i - 1].alias, &open))
      moqtss_member_remove(st, i - 1);
  moqtss_drop_if_empty(ss, k);
}
