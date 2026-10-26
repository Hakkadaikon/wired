#ifndef APP_MOQT_RUN_MOQTRUN_IMPL_H
#define APP_MOQT_RUN_MOQTRUN_IMPL_H

#include "app/moqt/run/moqtrun_impl_protos9.h"

int moqtrun_upf_chunk(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span c);
usz moqtrun_upf_pass(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span data);
int moqtrun_upf_join(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f, wired_span* data);
void moqtrun_upf_rest(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    int                  r,
    wired_span           rest,
    int                  fin);
void moqtrun_upf_feed(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    wired_span           data,
    int                  fin);
int moqtrun_upf_waits_data(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 rid);
void moqtrun_upf_torn_unheld(wired_moqt_hub* hub, const wired_wt_session* s);
int  moqtrun_upf_bind(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin);
wired_moqtrun_fetch* moqtrun_upf_by_data(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid);
int moqtrun_upf_data(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin);
moqctl_loc moqtrun_upf_ok_end(
    const wired_moqtrun_peer* pp, const moqfetch_ok* ok);
u64  moqtrun_tprop(wired_span props, u64 type, u64 dflt);
u32  moqtrun_tprops_check(wired_span props);
int  moqtrun_tprops_refused(wired_span props, u64* code);
void moqtrun_queue_request_ok_props(
    wired_moqtrun_peer* p, const wired_moqtrun_track* t, wired_span props);
wired_span moqtrun_track_props(const wired_moqtrun_track* t);
int        moqtrun_obj_mand(const wired_moqtrun_track* t, wired_span props);
wired_moqtrun_track* moqtrun_obj_mand_gate(
    wired_moqtrun_track* t, wired_span props);
void moqtrun_upf_mand(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
void moqtrun_upf_done_if(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
void moqtrun_upf_on_ok(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    wired_span           body);
wired_moqtrun_fetch* moqtrun_upf_by_req(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid);
int moqtrun_upf_rx(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    u64                 sid,
    wired_span          data,
    int                 fin);
wired_moqtrun_fetch* moqtrun_upf_by_live_data(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid);
void moqtrun_upf_on_reset(wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 sid);
void moqtrun_upf_detach(wired_moqt_hub* hub, const wired_wt_session* s);
void moqtrun_upf_retry(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
int  moqtrun_upf_tick(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
u64  moqtrun_upf_nt_refusal(
    wired_moqt_hub*           hub,
    const wired_moqtrun_peer* p,
    const moqfetch_req*       m,
    moqtrun_key               k);
void moqtrun_upf_no_track(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    const moqfetch_req* m,
    moqtrun_key         k);

extern const moqtrun_start_fn MOQTRUN_START_FNS[3];
extern const moqctl_params    MOQTRUN_UPF_NO_PARAMS;

#endif
