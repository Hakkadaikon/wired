/* Hub side of SSTS, ported from moqtail ee9753c apps/relay/src/server:
 * ssts/mod.rs (negotiation, decision record), ssts/switching_set.rs (set
 * membership), ssts/controller.rs (decide), subscription.rs (forward gate)
 * and client.rs (open-stream accounting). Differences, all forced by a
 * synchronous single-threaded hub:
 *
 * - Decisions are made at a group's first arrival (moqtss_prime) instead
 *   of by a controller task woken through a channel; a member joining
 *   mid-group gets that group's verdict at once (moqtss_join_prime: the
 *   recorded decision, else one made without observing). Backpressure
 *   observes at each group of the session's pacing set -- its lowest-slot
 *   active backpressure set (moqtss_pacer) -- and on the hub clock every
 *   MOQTSS_OBS_MS (moqtss_tick, moqtail's DECISION_INTERVAL), so the tier
 *   keeps moving while the pacing set is paused; every other backpressure
 *   set takes the current tier without observing.
 * - Group numbers are per set (each publisher counts its own groups), so
 *   each set keeps its own decision ring, pruned against its own largest
 *   group (moqtail keys one map by group across sets). The algorithm still
 *   runs jointly over the session's sets of that algorithm; only the
 *   missing set's pick is recorded.
 * - Stream depth is the number of subscriber subgroup streams the hub
 *   still holds open for the session's member tracks (relay entries with
 *   sub_stream_set): a stream counts from its open until the publisher's
 *   FIN is relayed (or it is shed / reset), not until the subscriber ACKs
 *   that FIN as moqtail's finish() does. One-shot streams (io.send_uni)
 *   never count. The observation takes the deepest set's count, not
 *   moqtail's sum over sets (moqssts_active_depth). The timeouts input is every
 * subscriber stream of the session the hub reset (busy shed, DELIVERY_TIMEOUT,
 * reliable stall: moqtss_note_shed) while the session had a pacing set, since
 * the pacing set's last decision -- in place of moqtail's discard-timeout
 * resets.
 * - The default algorithm's budget is the stricter of the subscriber
 *   connection's delivery-rate estimate (io.est_kbps, moqtail's bandwidth
 *   estimate) and wired_moqt_hub.ssts_cap_kbps; unlimited when both are 0.
 * - Membership is pruned lazily: a member whose subscription is no longer
 *   active (unsubscribed, cancelled, PUBLISH_DONE, either session closed)
 *   leaves its set at the session's next decision or assignment; an
 *   emptied set is deleted. A fresh SUBSCRIBE first leaves whatever set a
 *   dead subscription under the same alias held.
 * - Only request-stream subscriptions join sets (moqtrun.c refuses a
 *   control-stream one): those end with their publisher, while a
 *   control-stream subscription re-attaches silently to a re-PUBLISHed
 *   track whose group numbers restarted. A member subscription found in
 *   no set at prime (unreachable by that rule) stays gated and forwards
 *   nothing rather than everything. */

#include "app/moqt/run/moqtssts_run_impl.h"

static int moqtss_hub_runs(const wired_moqt_hub* hub, u64 id);
static int moqtss_offers(
    const wired_moqt_hub* hub, const wired_moqtrun_peer* p);
static usz moqtss_client_n(const moqctl_setup* m);
static int moqtss_unknown(
    const wired_moqt_hub* hub, const moqctl_params* params);
static int moqtss_unsettable_ssa(int unsettable, const moqctl_params* params);

/* The tick schedule belongs to one pacing period: it is dropped the moment
 * the session has no pacing set, so a set that becomes the pacer again
 * between two ticks starts with an arming tick, not an observation. Called
 * wherever set membership or properties change. */
void moqtss_sync_arm(moqtss_sess* ss) {
  ss->obs_armed = ss->obs_armed && moqtss_pacer(ss) >= 0;
}

/* ===== configuration and negotiation ===== */

void moqtss_hub_init(wired_moqt_hub* hub) {
  hub->ssts_algs     = 0;
  hub->ssts_alg_n    = 0;
  hub->ssts_cap_kbps = 0;
}

/* Session bit of an algorithm id (moqtss_sess.algs); 0 for one moqssts
 * does not implement. */
u8 moqtss_alg_bit(u64 id) {
  return (u8)((id == MOQSSTS_ALG_DEFAULT) |
              ((id == MOQSSTS_ALG_BACKPRESSURE) << 1));
}

static int moqtss_hub_runs(const wired_moqt_hub* hub, u64 id) {
  for (usz i = 0; i < hub->ssts_alg_n; i++)
    if (hub->ssts_algs[i] == id) return 1;
  return 0;
}

static int moqtss_offers(
    const wired_moqt_hub* hub, const wired_moqtrun_peer* p) {
  return hub->ssts_alg_n != 0 && p->ver == MOQVER_D22;
}

void moqtss_setup_opt(
    const wired_moqt_hub* hub, const wired_moqtrun_peer* p, moqctl_setup* s) {
  usz n = (usz)u64_min(hub->ssts_alg_n, MOQCTL_SSTS_MAX_ALGS);
  if (!moqtss_offers(hub, p)) return;
  for (usz i = 0; i < n; i++) s->ssts_algs[i] = hub->ssts_algs[i];
  s->ssts_alg_n = (u8)n;
  s->has_ssts   = 1;
}

/* Ids the client SETUP advertised (0 when the option was absent). */
static usz moqtss_client_n(const moqctl_setup* m) {
  return (usz)m->ssts_alg_n * (usz)(m->has_ssts != 0);
}

void moqtss_negotiate(
    const wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_setup* m) {
  u8  algs = 0;
  usz n    = moqtss_client_n(m);
  for (usz i = 0; i < n; i++)
    algs |= (u8)(moqtss_alg_bit(m->ssts_algs[i]) *
                 moqtss_hub_runs(hub, m->ssts_algs[i]));
  p->ssts.algs = (u8)(algs * (p->ver == MOQVER_D22));
}

void moqtss_sess_reset(moqtss_sess* s) {
  s->algs        = 0;
  s->timeouts    = 0;
  s->next_obs_ms = 0;
  s->obs_armed   = 0;
  moqssts_bp_init(&s->bp);
  for (usz k = 0; k < WIRED_MOQTRUN_SSTS_SETS; k++) s->sets[k].in_use = 0;
}

/* ===== parameter ===== */

/* The decoded SWITCHING_SET_ASSIGNMENT of params, else 0. */
const moqctl_ssa* moqtss_ssa_of(const moqctl_params* params) {
  const moqctl_param* a =
      moqctl_params_find(params, MOQCTL_PARAM_SWITCHING_SET_ASSIGNMENT);
  return a && a->enc == MOQCTL_PENC_SSA ? &a->ssa : 0;
}

/* An assignment reaching a hub that runs no SSTS. */
static int moqtss_unknown(
    const wired_moqt_hub* hub, const moqctl_params* params) {
  return hub->ssts_alg_n == 0 && moqtss_ssa_of(params);
}

int moqtss_take(const wired_moqt_hub* hub, int r, const moqctl_params* params) {
  if (r != MOQCTL_OK) return r;
  return moqtss_unknown(hub, params) ? MOQCTL_VIOLATION : MOQCTL_OK;
}

static int moqtss_unsettable_ssa(int unsettable, const moqctl_params* params) {
  return unsettable && moqtss_ssa_of(params);
}

u64 moqtss_sub_refusal(const moqctl_params* params, int unsettable, u64 prior) {
  if (prior != MOQTSS_ACCEPT) return prior;
  return moqtss_unsettable_ssa(unsettable, params)
             ? MOQCTL_ERR_UNSUPPORTED_EXTENSION
             : MOQTSS_ACCEPT;
}

/* ===== switching sets (switching_set.rs) ===== */

int moqtss_member_at(const moqtss_set* st, u64 alias) {
  for (usz i = 0; i < st->n; i++)
    if (st->m[i].alias == alias) return (int)i;
  return -1;
}
