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

#endif
