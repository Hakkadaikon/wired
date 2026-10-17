#include "app/moqt/run/moqtssts_run_impl.h"

static int moqtss_switching(
    const wired_moqtrun_sub* s, const moqctl_params* params);
static u64 moqtss_room_if(int room);
static u64 moqtss_fit(const moqtss_sess* ss, u64 alias, u64 set_id);
static int moqtss_refuses(
    const moqtss_sess*       ss,
    const wired_moqtrun_sub* s,
    const moqctl_params*     params,
    const moqctl_ssa*        a);

void moqtss_prune(wired_moqt_hub* hub, usz sidx) {
  moqtss_sess* ss = &hub->peers[sidx].ssts;
  for (usz k = 0; k < WIRED_MOQTRUN_SSTS_SETS; k++)
    if (ss->sets[k].in_use) moqtss_prune_set(hub, ss, sidx, k);
  moqtss_sync_arm(ss);
}

/* Open streams over slot k's members (the set's depth, client.rs). */
u64 moqtss_set_open(const wired_moqt_hub* hub, const moqtss_set* st, usz sidx) {
  u64 sum = 0, open;
  for (usz i = 0; i < st->n; i++)
    if (moqtss_live(hub, sidx, st->m[i].alias, &open)) sum += open;
  return sum;
}

/* ===== assignment (mod.rs validate_assignment, switching_set.rs) ===== */

/* SWITCH_FROM and SSTS do not compose (moqtail subscription.rs): a switch
 * party never joins a switching set. */
static int moqtss_switching(
    const wired_moqtrun_sub* s, const moqctl_params* params) {
  return s->sw_role != MOQTSW_ROLE_NONE ||
         moqctl_params_find(params, MOQCTL_PARAM_SWITCH_FROM) != 0;
}

static u64 moqtss_room_if(int room) {
  return room ? MOQTSS_ACCEPT : MOQCTL_ERR_INTERNAL_ERROR;
}

/* Room to join set set_id: a member slot in it, or a free set slot. */
u64 moqtss_room_in(const moqtss_sess* ss, u64 set_id) {
  int k = moqtss_set_by_id(ss, set_id);
  if (k >= 0) return moqtss_room_if(ss->sets[k].n < MOQSSTS_MAX_MEMBERS);
  return moqtss_room_if(moqtss_set_free(ss) >= 0);
}

/* A member stays in its set (re-tune); anyone else needs room. */
static u64 moqtss_fit(const moqtss_sess* ss, u64 alias, u64 set_id) {
  int cur = moqtss_set_of_alias(ss, alias);
  if (cur >= 0)
    return ss->sets[cur].set_id == set_id ? MOQTSS_ACCEPT
                                          : MOQCTL_ERR_UNSUPPORTED_EXTENSION;
  return moqtss_room_in(ss, set_id);
}

static int moqtss_refuses(
    const moqtss_sess*       ss,
    const wired_moqtrun_sub* s,
    const moqctl_params*     params,
    const moqctl_ssa*        a) {
  return !(ss->algs & moqtss_alg_bit(a->algorithm_id)) ||
         moqtss_switching(s, params);
}

/* The assignment's verdict, nothing joined: UNSUPPORTED_EXTENSION for an
 * algorithm the session did not negotiate, a switch party, or a track in
 * another set; INTERNAL_ERROR without room. Dead members leave first. */
u64 moqtss_check(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* s,
    const moqctl_params*     params,
    const moqctl_ssa*        a) {
  moqtss_sess* ss = &hub->peers[s->session_idx].ssts;
  moqtss_prune(hub, s->session_idx);
  if (moqtss_refuses(ss, s, params, a)) return MOQCTL_ERR_UNSUPPORTED_EXTENSION;
  return moqtss_fit(ss, s->track_alias, a->set_id);
}

/* Joins (or re-tunes) s per a; moqtss_check accepted it. */
void moqtss_join(
    wired_moqt_hub* hub, wired_moqtrun_sub* s, const moqctl_ssa* a) {
  moqtss_sess* ss = &hub->peers[s->session_idx].ssts;
  int          k  = moqtss_set_of_alias(ss, s->track_alias);
  if (k < 0) k = (int)moqtss_set_claim(ss, a->set_id);
  moqtss_unplace(&ss->sets[k], s->track_alias);
  moqtss_member_insert(&ss->sets[k], s->track_alias, a->threshold_kbps);
  moqtss_set_props(&ss->sets[k], a);
  moqtss_sync_arm(ss);
  s->ssts_on = 1;
}

void moqtss_sub_reset(wired_moqtrun_sub* s) {
  s->ssts_on    = 0;
  s->ssts_base  = 0;
  s->ssts_known = 0;
  s->ssts_fwd   = 0;
}

void moqtss_sub_leave(wired_moqt_hub* hub, wired_moqtrun_sub* s) {
  moqtss_sub_reset(s);
  moqtss_leave(&hub->peers[s->session_idx].ssts, s->track_alias);
}
