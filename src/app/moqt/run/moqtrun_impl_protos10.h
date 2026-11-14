#ifndef APP_MOQT_RUN_MOQTRUN_IMPL_PART11_H
#define APP_MOQT_RUN_MOQTRUN_IMPL_PART11_H

#include "app/moqt/run/moqtrun_impl_protos9.h"

void moqtrun_upd_drop_now(wired_moqt_hub* hub, wired_moqtrun_peer* p);
void moqtrun_upd_settle(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_track* t);
void moqtrun_upd_rdv_ok(wired_moqtrun_peer* p, const wired_moqtrun_track* t);
void moqtrun_upd_rdv_refuse(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 code);
void moqtrun_upd_rdv_resolve(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_track* t);
int moqtrun_resume_wait_upd(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_track* t);
void moqtrun_pubst_moves(wired_moqt_hub* hub);
int  moqtrun_upf_owner_free(const wired_moqtrun_peer* op);
void moqtrun_upf_moves(wired_moqt_hub* hub);
int  moqtrun_upf_old_data(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid, int fin);

int moqtrun_disc_live_mask(wired_moqt_hub* hub, u64 kind, u64* mask);
int moqtrun_disc_ns_masks(wired_moqt_hub* hub, u64* subs, u64* pubs);
u64 moqtrun_req_used_word(wired_moqt_hub* hub, usz w);

#endif
