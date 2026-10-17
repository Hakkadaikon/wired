#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_peer_matches_wt(
    const wired_moqtrun_peer* p, const wired_wt_session* s);

/* ===================== peer table ===================== */

static int moqtrun_peer_matches_wt(
    const wired_moqtrun_peer* p, const wired_wt_session* s) {
  return p->in_use && p->wt == s;
}

wired_moqtrun_peer* moqtrun_find_by_wt(
    wired_moqt_hub* hub, wired_wt_session* s) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (moqtrun_peer_matches_wt(&hub->peers[i], s)) return &hub->peers[i];
  return 0;
}

wired_moqtrun_peer* moqtrun_alloc(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (!hub->peers[i].in_use) return &hub->peers[i];
  return 0;
}

void moqtrun_peer_clear_relays(wired_moqtrun_peer* p) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    moqtrun_track_clear_relays(&p->tracks[t]);
}

void moqtrun_reqs_clear(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) hub->reqs[i].in_use = 0;
}

void moqtrun_rdv_clear(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++) hub->rdv[i].in_use = 0;
}

void moqtrun_up_clear(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++) hub->ups[i].in_use = 0;
}
