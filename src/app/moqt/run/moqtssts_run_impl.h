#ifndef APP_MOQT_RUN_MOQTSSTS_RUN_IMPL_H
#define APP_MOQT_RUN_MOQTSSTS_RUN_IMPL_H

/* Internal to the moqtssts_run*.c pieces of this directory: shared types,
 * macros and the functions and tables more than one piece uses. Not public API.
 */

#include "app/moqt/run/moqtssts_run.h"
#include "app/moqt/run/moqtswitch.h"
#include "app/moqt/ver/moqver.h"
#include "common/bytes/util/num.h"

#define MOQTSS_WIN 16u /* verdict window per subscription (u16 masks) */
#define MOQTSS_OBS_MS \
  100u /* tick observation period (moqtail DECISION_INTERVAL) */

/* The algorithm's view of the session's sets of one algorithm (mod.rs
 * decision_snapshot). */
typedef struct {
  moqssts_set sets[WIRED_MOQTRUN_SSTS_SETS];
  u64         open[WIRED_MOQTRUN_SSTS_SETS];
  usz         slot[WIRED_MOQTRUN_SSTS_SETS];
  int         out[WIRED_MOQTRUN_SSTS_SETS];
  usz         n;
} moqtss_view;

int  moqtss_pacer(const moqtss_sess* ss);
void moqtss_join_prime(wired_moqt_hub* hub, wired_moqtrun_sub* s, u64 g);

void              moqtss_sync_arm(moqtss_sess* ss);
u8                moqtss_alg_bit(u64 id);
const moqctl_ssa* moqtss_ssa_of(const moqctl_params* params);
int               moqtss_member_at(const moqtss_set* st, u64 alias);
int               moqtss_set_of_alias(const moqtss_sess* ss, u64 alias);
int               moqtss_set_by_id(const moqtss_sess* ss, u64 set_id);
int               moqtss_set_free(const moqtss_sess* ss);
usz               moqtss_set_claim(moqtss_sess* ss, u64 set_id);
void              moqtss_drop_if_empty(moqtss_sess* ss, usz k);
void              moqtss_member_remove(moqtss_set* st, usz i);
void              moqtss_member_insert(moqtss_set* st, u64 alias, u64 kbps);
void              moqtss_unplace(moqtss_set* st, u64 alias);
void              moqtss_leave(moqtss_sess* ss, u64 alias);
void              moqtss_set_props(moqtss_set* st, const moqctl_ssa* a);
int  moqtss_live(const wired_moqt_hub* hub, usz sidx, u64 alias, u64* open);
void moqtss_prune_set(
    const wired_moqt_hub* hub, moqtss_sess* ss, usz sidx, usz k);
void moqtss_prune(wired_moqt_hub* hub, usz sidx);
u64  moqtss_set_open(const wired_moqt_hub* hub, const moqtss_set* st, usz sidx);
u64  moqtss_room_in(const moqtss_sess* ss, u64 set_id);
u64  moqtss_check(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* s,
    const moqctl_params*     params,
    const moqctl_ssa*        a);
void moqtss_join(
    wired_moqt_hub* hub, wired_moqtrun_sub* s, const moqctl_ssa* a);
int               moqtss_pacer(const moqtss_sess* ss);
const moqtss_dec* moqtss_ring_find(const moqtss_set* st, u64 g);
void              moqtss_ring_record(moqtss_set* st, u64 g, u64 pick);
void              moqtss_view_add(
    const wired_moqt_hub* hub,
    moqtss_view*          v,
    const moqtss_set*     st,
    usz                   sidx,
    usz                   k);
void moqtss_view_of(
    const wired_moqt_hub* hub, usz sidx, u64 alg, moqtss_view* v);
u64  moqtss_decide_as(wired_moqt_hub* hub, usz sidx, usz k, u64 g, int pace);
u64  moqtss_pick(wired_moqt_hub* hub, usz sidx, usz k, u64 g);
void moqtss_rebase_up(wired_moqtrun_sub* s, u64 g);
void moqtss_rebase_down(wired_moqtrun_sub* s, u64 g);
int  moqtss_below_fits(const wired_moqtrun_sub* s, u64 g);
void moqtss_join_prime(wired_moqt_hub* hub, wired_moqtrun_sub* s, u64 g);

#endif
