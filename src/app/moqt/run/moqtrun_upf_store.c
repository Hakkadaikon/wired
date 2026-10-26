#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_upf_store_key(wired_moqtrun_upf_leg* l, moqtrun_key k);
static void moqtrun_upf_store(
    wired_moqt_hub*      hub,
    wired_moqtrun_fetch* f,
    wired_moqtrun_peer*  pp,
    i64                  sid,
    const moqfetch_req*  m);

/* The leg state of f, a fetches[] slot. */
wired_moqtrun_upf_leg* moqtrun_upf_leg_of(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f) {
  return &hub->upf_legs[f - hub->fetches];
}

static void moqtrun_upf_store_key(wired_moqtrun_upf_leg* l, moqtrun_key k) {
  l->ns_len   = k.ns.n;
  l->name_len = k.name.n;
  bytes_memcpy(l->ns, k.ns.p, k.ns.n);
  bytes_memcpy(l->name, k.name.p, k.name.n);
}

/* f's leg starts: the FETCH m went to pp on stream sid. */
static void moqtrun_upf_store(
    wired_moqt_hub*      hub,
    wired_moqtrun_fetch* f,
    wired_moqtrun_peer*  pp,
    i64                  sid,
    const moqfetch_req*  m) {
  f->up_state   = WIRED_MOQTRUN_UPF_SENT;
  f->up_wt      = pp->wt;
  f->up_req_sid = (u64)sid;
  f->up_rid     = m->request_id;
  bytes_memset(
      &moqtrun_upf_leg_of(hub, f)->in, 0, sizeof(wired_moqtrun_ctl_asm));
  f->up_data_open = 0;
  f->up_data_end  = 0;
  f->has_up_last  = 0;
  f->up_pl_left   = 0;
  f->up_pl_at     = 0;
  bytes_memset(&f->up_seq, 0, sizeof f->up_seq);
  f->up_seq.descending = f->descending;
  f->up_seq.eor_timed_out =
      (moqver_caps(pp->ver) & MOQVER_CAP_EOR_TIMED_OUT) != 0;
  f->up_deadline_ms = hub->live.last_now_ms + f->up_budget_ms;
}

/* One FETCH for rl of k to pp (0: none to ask), f's leg from now on; 0
 * when it did not go out. */
int moqtrun_upf_open(
    wired_moqt_hub*        hub,
    wired_moqtrun_fetch*   f,
    wired_moqtrun_peer*    pp,
    moqtrun_key            k,
    const moqctl_rangeloc* rl,
    const moqctl_params*   params) {
  moqfetch_req m   = {0};
  usz          off = 0;
  if (!pp) {
    return 0;
  }
  m.fetch_type = MOQFETCH_STANDALONE;
  m.track.name = k.name;
  moqctl_ns_take(k.ns, &off, &m.track.ns);
  m.range = *rl;
  moqtrun_upf_params(
      params, moqtrun_peer_max_rngf(pp), f->descending, &m.params);
  i64 sid = moqtrun_upf_send(hub, pp, &m);
  if (sid < 0) {
    return 0;
  }
  moqtrun_upf_store(hub, f, pp, sid, &m);
  moqtrun_upf_store_key(moqtrun_upf_leg_of(hub, f), k);
  return 1;
}

/* ----- when a held track's fetch asks upstream ----- */

/* min(FILL_TIMEOUT, WIRED_MOQTRUN_UPFETCH_BUDGET_MS); FILL_TIMEOUT 0 asks
 * nothing upstream and reports what the cache lacks as timed out
 * (draft-22 9.20.5). */
void moqtrun_upf_budget(wired_moqtrun_fetch* f, int has, u64 ms) {
  f->up_budget_ms = has ? u64_min(ms, WIRED_MOQTRUN_UPFETCH_BUDGET_MS)
                        : WIRED_MOQTRUN_UPFETCH_BUDGET_MS;
  f->up_tmo       = has && ms == 0;
}

void moqtrun_upf_budget_of(
    wired_moqtrun_fetch* f, const moqctl_params* params) {
  const moqctl_param* ft =
      moqctl_params_find(params, MOQCTL_PARAM_FILL_TIMEOUT);
  moqtrun_upf_budget(f, ft != 0, ft ? ft->vi : 0);
}
