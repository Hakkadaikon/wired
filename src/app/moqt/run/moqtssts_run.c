#include "app/moqt/run/moqtssts_run.h"

#include "app/moqt/run/moqtswitch.h"
#include "app/moqt/ver/moqver.h"
#include "common/bytes/util/num.h"

/* Hub side of SSTS, ported from moqtail ee9753c apps/relay/src/server:
 * ssts/mod.rs (negotiation, decision record), ssts/switching_set.rs (set
 * membership), ssts/controller.rs (decide), subscription.rs (forward gate)
 * and client.rs (open-stream accounting). Differences, all forced by a
 * synchronous single-threaded hub:
 *
 * - Decisions are made at a group's first arrival (moqtss_prime) instead
 *   of by a controller task woken through a channel; there is no 100 ms
 *   DECISION_INTERVAL tick (moqtail also observes on every tick).
 *   Backpressure observes once per group of the session's pacing set --
 *   its lowest-slot active backpressure set (moqtss_pacer); every other
 *   backpressure set takes the current tier without observing, so two
 *   sharers do not advance the tier twice per group time.
 *   Known limitation: a pacing set that stays live (active, members
 *   subscribed) but sends no groups -- a paused share -- freezes the
 *   shared tier for every other backpressure set of the session, which
 *   only hold it; and the session's reset count keeps accumulating over
 *   their groups, consumed in one observation at the pacing set's next
 *   decision (one burst of timeouts, possibly several downshift steps'
 *   worth of evidence at once). Pinned by
 *   test_moqtrun_ssts_known_limit_paused_pacer_freezes_tier.
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
 * - The default algorithm has no bandwidth estimate: its budget is
 *   wired_moqt_hub.ssts_cap_kbps, unlimited when 0.
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

#define MOQTSS_WIN 16u /* verdict window per subscription (u16 masks) */

/* ===== configuration and negotiation ===== */

void moqtss_hub_init(wired_moqt_hub* hub) {
  hub->ssts_algs     = 0;
  hub->ssts_alg_n    = 0;
  hub->ssts_cap_kbps = 0;
}

/* Session bit of an algorithm id (moqtss_sess.algs); 0 for one moqssts
 * does not implement. */
static u8 moqtss_alg_bit(u64 id) {
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
  s->algs     = 0;
  s->timeouts = 0;
  moqssts_bp_init(&s->bp);
  for (usz k = 0; k < WIRED_MOQTRUN_SSTS_SETS; k++) s->sets[k].in_use = 0;
}

/* ===== parameter ===== */

/* The decoded SWITCHING_SET_ASSIGNMENT of params, else 0. */
static const moqctl_ssa* moqtss_ssa_of(const moqctl_params* params) {
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

static int moqtss_member_at(const moqtss_set* st, u64 alias) {
  for (usz i = 0; i < st->n; i++)
    if (st->m[i].alias == alias) return (int)i;
  return -1;
}

static int moqtss_set_has(const moqtss_set* st, u64 alias) {
  return st->in_use && moqtss_member_at(st, alias) >= 0;
}

/* Slot of the set holding alias, else -1 (a track is in one set). */
static int moqtss_set_of_alias(const moqtss_sess* ss, u64 alias) {
  for (usz k = 0; k < WIRED_MOQTRUN_SSTS_SETS; k++)
    if (moqtss_set_has(&ss->sets[k], alias)) return (int)k;
  return -1;
}

static int moqtss_set_is(const moqtss_set* st, u64 set_id) {
  return st->in_use && st->set_id == set_id;
}

static int moqtss_set_by_id(const moqtss_sess* ss, u64 set_id) {
  for (usz k = 0; k < WIRED_MOQTRUN_SSTS_SETS; k++)
    if (moqtss_set_is(&ss->sets[k], set_id)) return (int)k;
  return -1;
}

static int moqtss_set_free(const moqtss_sess* ss) {
  for (usz k = 0; k < WIRED_MOQTRUN_SSTS_SETS; k++)
    if (!ss->sets[k].in_use) return (int)k;
  return -1;
}

/* No decision recorded, no largest group: a fresh numbering. */
static void moqtss_ring_clear(moqtss_set* st) {
  for (usz i = 0; i < WIRED_MOQTRUN_SSTS_RING; i++) st->dec[i].used = 0;
  st->has_largest = 0;
}

/* The set set_id's slot, claimed fresh (empty, no decisions) when it does
 * not exist. The caller checked a slot is available (moqtss_room_in). */
static usz moqtss_set_claim(moqtss_sess* ss, u64 set_id) {
  int k = moqtss_set_by_id(ss, set_id);
  if (k >= 0) return (usz)k;
  k                  = moqtss_set_free(ss);
  ss->sets[k].in_use = 1;
  ss->sets[k].set_id = set_id;
  ss->sets[k].n      = 0;
  moqtss_ring_clear(&ss->sets[k]);
  return (usz)k;
}

static void moqtss_drop_if_empty(moqtss_sess* ss, usz k) {
  if (!ss->sets[k].n) ss->sets[k].in_use = 0;
}

static void moqtss_member_remove(moqtss_set* st, usz i) {
  for (usz j = i + 1; j < st->n; j++) st->m[j - 1] = st->m[j];
  st->n--;
}

/* First index whose threshold exceeds kbps: the ascending insert point. */
static usz moqtss_insert_at(const moqtss_set* st, u64 kbps) {
  usz j = 0;
  while (j < st->n && st->m[j].threshold_kbps <= kbps) j++;
  return j;
}

/* Inserts (alias, kbps) keeping the ladder ascending; room was checked. */
static void moqtss_member_insert(moqtss_set* st, u64 alias, u64 kbps) {
  usz j = moqtss_insert_at(st, kbps);
  for (usz i = st->n; i > j; i--) st->m[i] = st->m[i - 1];
  st->m[j].alias          = alias;
  st->m[j].threshold_kbps = kbps;
  st->n++;
}

static void moqtss_unplace(moqtss_set* st, u64 alias) {
  int at = moqtss_member_at(st, alias);
  if (at >= 0) moqtss_member_remove(st, (usz)at);
}

/* alias leaves whatever set holds it; an emptied set is deleted. */
static void moqtss_leave(moqtss_sess* ss, u64 alias) {
  int k = moqtss_set_of_alias(ss, alias);
  if (k < 0) return;
  moqtss_unplace(&ss->sets[k], alias);
  moqtss_drop_if_empty(ss, (usz)k);
}

/* Set properties: the most recently received assignment wins. */
static void moqtss_set_props(moqtss_set* st, const moqctl_ssa* a) {
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
static int moqtss_live(
    const wired_moqt_hub* hub, usz sidx, u64 alias, u64* open) {
  *open = 0;
  for (usz p = 0; p < WIRED_MOQTRUN_MAX_SESSIONS; p++)
    if (moqtss_on_peer(&hub->peers[p], sidx, alias, open)) return 1;
  return 0;
}

/* Drops slot k's members whose subscription is gone; the set itself once
 * empty (switching_set.rs remove). */
static void moqtss_prune_set(
    const wired_moqt_hub* hub, moqtss_sess* ss, usz sidx, usz k) {
  moqtss_set* st = &ss->sets[k];
  u64         open;
  for (usz i = st->n; i > 0; i--)
    if (!moqtss_live(hub, sidx, st->m[i - 1].alias, &open))
      moqtss_member_remove(st, i - 1);
  moqtss_drop_if_empty(ss, k);
}

static void moqtss_prune(wired_moqt_hub* hub, usz sidx) {
  moqtss_sess* ss = &hub->peers[sidx].ssts;
  for (usz k = 0; k < WIRED_MOQTRUN_SSTS_SETS; k++)
    if (ss->sets[k].in_use) moqtss_prune_set(hub, ss, sidx, k);
}

/* Open streams over slot k's members (the set's depth, client.rs). */
static u64 moqtss_set_open(
    const wired_moqt_hub* hub, const moqtss_set* st, usz sidx) {
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
static u64 moqtss_room_in(const moqtss_sess* ss, u64 set_id) {
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
static u64 moqtss_check(
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
static void moqtss_join(
    wired_moqt_hub* hub, wired_moqtrun_sub* s, const moqctl_ssa* a) {
  moqtss_sess* ss = &hub->peers[s->session_idx].ssts;
  int          k  = moqtss_set_of_alias(ss, s->track_alias);
  if (k < 0) k = (int)moqtss_set_claim(ss, a->set_id);
  moqtss_unplace(&ss->sets[k], s->track_alias);
  moqtss_member_insert(&ss->sets[k], s->track_alias, a->threshold_kbps);
  moqtss_set_props(&ss->sets[k], a);
  s->ssts_on = 1;
}

void moqtss_sub_reset(wired_moqtrun_sub* s) {
  s->ssts_on    = 0;
  s->ssts_base  = 0;
  s->ssts_known = 0;
  s->ssts_fwd   = 0;
}

u64 moqtss_on_subscribe(
    wired_moqt_hub* hub, wired_moqtrun_sub* s, const moqctl_params* params) {
  const moqctl_ssa* a = moqtss_ssa_of(params);
  moqtss_sub_reset(s);
  moqtss_leave(&hub->peers[s->session_idx].ssts, s->track_alias);
  if (!a) return MOQTSS_ACCEPT;
  u64 code = moqtss_check(hub, s, params, a);
  if (code == MOQTSS_ACCEPT) moqtss_join(hub, s, a);
  return code;
}

static u64 moqtss_upd_verdict(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* s,
    const moqctl_params*     params,
    const moqctl_ssa*        a,
    int                      settable) {
  if (!settable) return MOQCTL_ERR_UNSUPPORTED_EXTENSION;
  return moqtss_check(hub, s, params, a);
}

u64 moqtss_upd_check(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* s,
    const moqctl_params*     params,
    int                      settable,
    u64                      prior) {
  const moqctl_ssa* a = moqtss_ssa_of(params);
  if (prior != MOQTSS_ACCEPT || !a) return prior;
  return moqtss_upd_verdict(hub, s, params, a, settable);
}

void moqtss_on_update(
    wired_moqt_hub* hub, wired_moqtrun_sub* s, const moqctl_params* params) {
  const moqctl_ssa* a = moqtss_ssa_of(params);
  if (a) moqtss_join(hub, s, a);
}

int moqtss_sub_in_set(const wired_moqtrun_sub* s) { return s->ssts_on; }

/* ===== congestion evidence (client.rs StreamTimeout) ===== */

static int moqtss_peer_is(const wired_moqtrun_peer* p, wired_wt_session* wt) {
  return p->in_use && p->wt == wt;
}

static int moqtss_active(const moqtss_set* st) {
  return st->activate > 0 && st->n >= st->activate;
}

static int moqtss_paces(const moqtss_set* st) {
  return st->in_use && st->algorithm_id == MOQSSTS_ALG_BACKPRESSURE &&
         moqtss_active(st);
}

/* The session's pacing set: its lowest-slot active backpressure set, the
 * one whose decisions advance the tier (-1: none). */
static int moqtss_pacer(const moqtss_sess* ss) {
  for (usz k = 0; k < WIRED_MOQTRUN_SSTS_SETS; k++)
    if (moqtss_paces(&ss->sets[k])) return (int)k;
  return -1;
}

/* Counted only while a pacing set exists to consume it: no stale
 * evidence for a backpressure set that becomes active later. */
void moqtss_note_shed(wired_moqt_hub* hub, wired_wt_session* wt) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (moqtss_peer_is(&hub->peers[i], wt))
      hub->peers[i].ssts.timeouts += moqtss_pacer(&hub->peers[i].ssts) >= 0;
}

/* ===== decisions (controller.rs, mod.rs record_group_decision) ===== */

/* Older than the set's largest - KEEP: pruned (moqtail DECISION_WINDOW). */
static int moqtss_dec_stale(const moqtss_set* st, const moqtss_dec* e) {
  return e->group + WIRED_MOQTRUN_SSTS_KEEP < st->largest;
}

static int moqtss_dec_hit(const moqtss_dec* e, u64 g) {
  return e->used && e->group == g;
}

static const moqtss_dec* moqtss_ring_find(const moqtss_set* st, u64 g) {
  for (usz i = 0; i < WIRED_MOQTRUN_SSTS_RING; i++)
    if (moqtss_dec_hit(&st->dec[i], g)) return &st->dec[i];
  return 0;
}

/* moqtail record_group_decision: entries older than largest - KEEP go
 * whenever a decision is recorded (the one being written is kept). */
static void moqtss_ring_prune(moqtss_set* st) {
  for (usz i = 0; i < WIRED_MOQTRUN_SSTS_RING; i++)
    if (moqtss_dec_stale(st, &st->dec[i])) st->dec[i].used = 0;
}

static moqtss_dec* moqtss_ring_lowest(moqtss_set* st) {
  moqtss_dec* low = &st->dec[0];
  for (usz i = 1; i < WIRED_MOQTRUN_SSTS_RING; i++)
    if (st->dec[i].group < low->group) low = &st->dec[i];
  return low;
}

/* The entry to (re)use: a free one, else the lowest group's. */
static moqtss_dec* moqtss_ring_slot(moqtss_set* st) {
  for (usz i = 0; i < WIRED_MOQTRUN_SSTS_RING; i++)
    if (!st->dec[i].used) return &st->dec[i];
  return moqtss_ring_lowest(st);
}

static void moqtss_note_largest(moqtss_set* st, u64 g) {
  st->largest     = st->has_largest ? u64_max(st->largest, g) : g;
  st->has_largest = 1;
}

static void moqtss_ring_record(moqtss_set* st, u64 g, u64 pick) {
  moqtss_note_largest(st, g);
  moqtss_ring_prune(st);
  moqtss_dec* e = moqtss_ring_slot(st);
  e->used       = 1;
  e->group      = g;
  e->pick       = pick;
}

/* The algorithm's view of the session's sets of one algorithm (mod.rs
 * decision_snapshot). */
typedef struct {
  moqssts_set sets[WIRED_MOQTRUN_SSTS_SETS];
  u64         open[WIRED_MOQTRUN_SSTS_SETS];
  usz         slot[WIRED_MOQTRUN_SSTS_SETS];
  int         out[WIRED_MOQTRUN_SSTS_SETS];
  usz         n;
} moqtss_view;

static void moqtss_view_add(
    const wired_moqt_hub* hub,
    moqtss_view*          v,
    const moqtss_set*     st,
    usz                   sidx,
    usz                   k) {
  moqssts_set* d  = &v->sets[v->n];
  d->set_id       = st->set_id;
  d->algorithm_id = st->algorithm_id;
  d->weight       = st->weight;
  d->activate     = st->activate;
  d->rank         = st->rank;
  d->n_members    = st->n;
  for (usz i = 0; i < st->n; i++) {
    d->m[i].track_id       = st->m[i].alias;
    d->m[i].threshold_kbps = st->m[i].threshold_kbps;
  }
  v->open[v->n] = moqtss_set_open(hub, st, sidx);
  v->slot[v->n] = k;
  v->n++;
}

static int moqtss_view_wants(const moqtss_set* st, u64 alg) {
  return st->in_use && st->algorithm_id == alg;
}

static void moqtss_view_of(
    const wired_moqt_hub* hub, usz sidx, u64 alg, moqtss_view* v) {
  const moqtss_sess* ss = &hub->peers[sidx].ssts;
  v->n                  = 0;
  for (usz k = 0; k < WIRED_MOQTRUN_SSTS_SETS; k++)
    if (moqtss_view_wants(&ss->sets[k], alg))
      moqtss_view_add(hub, v, &ss->sets[k], sidx, k);
}

/* A non-pacing backpressure set's pick: the current tier, clamped to its
 * ladder, nothing when inactive (moqssts_bp_decide without observing). */
static int moqtss_hold_pick(u64 tier, const moqssts_set* s) {
  if (!moqssts_set_active(s)) return MOQSSTS_NONE;
  return (int)u64_min(tier, s->n_members - 1);
}

static void moqtss_bp_hold(const moqtss_sess* ss, moqtss_view* v) {
  for (usz j = 0; j < v->n; j++)
    v->out[j] = moqtss_hold_pick(ss->bp.tier, &v->sets[j]);
}

/* Runs alg over the view (budget: the cap alone, see the file note). The
 * pacing set's backpressure decision observes and consumes the session's
 * reset count; any other backpressure set holds the tier. */
static void moqtss_view_run(
    const wired_moqt_hub* hub,
    moqtss_sess*          ss,
    u64                   alg,
    moqtss_view*          v,
    int                   pace) {
  if (alg != MOQSSTS_ALG_BACKPRESSURE) {
    moqssts_default_decide(
        moqssts_budget_kbps(0, hub->ssts_cap_kbps), v->sets, v->n, v->out);
    return;
  }
  if (!pace) {
    moqtss_bp_hold(ss, v);
    return;
  }
  moqssts_bp_decide(&ss->bp, v->sets, v->n, v->open, ss->timeouts, v->out);
  ss->timeouts = 0;
}

static u64 moqtss_pick_alias(const moqtss_view* v, usz j) {
  if (v->out[j] < 0) return MOQTSS_PICK_NONE;
  return v->sets[j].m[v->out[j]].track_id;
}

/* The view's pick for set slot k (NONE when k was not in the view: an
 * algorithm no session list owns, controller.rs "unowned"). */
static u64 moqtss_view_pick(const moqtss_view* v, usz k) {
  for (usz j = 0; j < v->n; j++)
    if (v->slot[j] == k) return moqtss_pick_alias(v, j);
  return MOQTSS_PICK_NONE;
}

/* Decides group g for set slot k now (one algorithm run, joint over the
 * session's sets of k's algorithm) and records it: final for (k, g). */
static u64 moqtss_decide(wired_moqt_hub* hub, usz sidx, usz k, u64 g) {
  moqtss_sess* ss = &hub->peers[sidx].ssts;
  moqtss_view  v;
  moqtss_prune(hub, sidx);
  moqtss_view_of(hub, sidx, ss->sets[k].algorithm_id, &v);
  moqtss_view_run(
      hub, ss, ss->sets[k].algorithm_id, &v, moqtss_pacer(ss) == (int)k);
  u64 pick = moqtss_view_pick(&v, k);
  moqtss_ring_record(&ss->sets[k], g, pick);
  return pick;
}

/* The alias set slot k forwards for group g, deciding g now if needed. */
static u64 moqtss_pick(wired_moqt_hub* hub, usz sidx, usz k, u64 g) {
  const moqtss_dec* e = moqtss_ring_find(&hub->peers[sidx].ssts.sets[k], g);
  return e ? e->pick : moqtss_decide(hub, sidx, k, g);
}

/* ===== per-subscription verdict window ===== */

static u16 moqtss_shr(u16 v, u64 k) {
  return k >= MOQTSS_WIN ? 0 : (u16)(v >> k);
}

/* g past the window's top: slide it up so g is its last bit. */
static void moqtss_rebase_up(wired_moqtrun_sub* s, u64 g) {
  if (g < s->ssts_base + MOQTSS_WIN) return;
  u64 k         = g - (MOQTSS_WIN - 1) - s->ssts_base;
  s->ssts_known = moqtss_shr(s->ssts_known, k);
  s->ssts_fwd   = moqtss_shr(s->ssts_fwd, k);
  s->ssts_base  = g - (MOQTSS_WIN - 1);
}

/* g below the window (a late older group): slide it down to g. */
static void moqtss_rebase_down(wired_moqtrun_sub* s, u64 g) {
  if (g >= s->ssts_base) return;
  u64 k         = s->ssts_base - g;
  s->ssts_known = (u16)(s->ssts_known << k);
  s->ssts_fwd   = (u16)(s->ssts_fwd << k);
  s->ssts_base  = g;
}

/* g below the window fits only while no recorded verdict would be pushed
 * out of the top. */
static int moqtss_below_fits(const wired_moqtrun_sub* s, u64 g) {
  u64 k = s->ssts_base - g;
  return k < MOQTSS_WIN && (s->ssts_known >> (MOQTSS_WIN - k)) == 0;
}

/* A stamp below a window it cannot shift is dropped: the newest verdicts
 * stay, and the late group is not forwarded. */
static int moqtss_stampable(const wired_moqtrun_sub* s, u64 g) {
  return g >= s->ssts_base || moqtss_below_fits(s, g);
}

static void moqtss_stamp(wired_moqtrun_sub* s, u64 g, int fwd) {
  if (!s->ssts_known) s->ssts_base = g;
  if (!moqtss_stampable(s, g)) return;
  moqtss_rebase_up(s, g);
  moqtss_rebase_down(s, g);
  u16 bit       = (u16)(1u << (g - s->ssts_base));
  s->ssts_known = (u16)(s->ssts_known | bit);
  s->ssts_fwd   = (u16)((s->ssts_fwd & ~bit) | (bit * (fwd != 0)));
}

static u32 moqtss_bit_of(const wired_moqtrun_sub* s, u64 g) {
  return g >= s->ssts_base && g - s->ssts_base < MOQTSS_WIN
             ? 1u << (g - s->ssts_base)
             : 0;
}

int moqtss_sub_pass(const wired_moqtrun_sub* s, u64 g) {
  if (!s->ssts_on) return 1;
  return (moqtss_bit_of(s, g) & s->ssts_known & s->ssts_fwd) != 0;
}

/* ===== the gate's entry (subscription.rs ssts_gate_allows) ===== */

static int moqtss_primes(const wired_moqtrun_sub* s) {
  return s->active && s->ssts_on;
}

/* s's verdict for g. k < 0 (a member whose set is gone) is unreachable:
 * control-stream subscriptions, the only ones that re-attach, are
 * refused; were it reached, s is stamped "not this group" and stays gated
 * rather than forwarding everything. */
static void moqtss_prime_sub(wired_moqt_hub* hub, wired_moqtrun_sub* s, u64 g) {
  if (!moqtss_primes(s)) return;
  int k = moqtss_set_of_alias(&hub->peers[s->session_idx].ssts, s->track_alias);
  u64 pick =
      k < 0 ? MOQTSS_PICK_NONE : moqtss_pick(hub, s->session_idx, (usz)k, g);
  moqtss_stamp(s, g, pick == s->track_alias);
}

void moqtss_prime(wired_moqt_hub* hub, wired_moqtrun_track* track, u64 g) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    moqtss_prime_sub(hub, &track->subs[i], g);
}
