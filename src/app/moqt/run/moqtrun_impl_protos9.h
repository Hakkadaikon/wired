#ifndef APP_MOQT_RUN_MOQTRUN_IMPL_PART10_H
#define APP_MOQT_RUN_MOQTRUN_IMPL_PART10_H

#include "app/moqt/run/moqtrun_impl_protos8.h"

void moqtrun_ctl_urgency(wired_moqt_io* io, wired_wt_session* s, u64 sid);
void moqtrun_sgt_arm(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* track,
    const wired_moqtrun_relay* relay,
    int                        fin);
void moqtrun_sgt_tick(wired_moqt_hub* hub, u64 now_ms);
usz  moqtrun_upd_msg(
    wired_moqtrun_peer* pp, const moqctl_params* params, u8* msg, usz cap);
wired_moqtrun_req* moqtrun_pub_req(
    wired_moqt_hub* hub, const wired_moqtrun_track* t);
int moqtrun_pubupd_send(
    wired_moqt_hub* hub, wired_moqtrun_req* q, const moqctl_params* params);
void moqtrun_pub_resume(wired_moqt_hub* hub, wired_moqtrun_track* t);
int  moqtrun_req_upd_answer(const wired_moqtrun_req* q, u64 type);
void moqtrun_dispatch_upd_ok(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
void moqtrun_dispatch_upd_err(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
int moqtrun_obj_gone(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l);
wired_moqtrun_track* moqtrun_gone_gate(
    wired_moqt_hub* hub, wired_moqtrun_track* t, moqctl_loc l);
int moqtrun_fsel_pass(
    const wired_moqtrun_rngrow* rows, usz n, const moqtrun_fsel_obj* o);
moqctl_loc moqtrun_fsel_skip(
    moqcache*                   c,
    u64                         tag,
    const wired_moqtrun_rngrow* rows,
    usz                         n,
    moqctl_loc                  from,
    moqctl_loc                  end);
moqctl_loc moqtrun_fsel_fskip(
    moqcache* c, const wired_moqtrun_fetch* f, moqctl_loc from, moqctl_loc end);
void moqtrun_fsel_keep(
    wired_moqtrun_fetch* f, const wired_moqtrun_rngrow* rows, usz n);
usz moqtrun_fsel_rows(const moqctl_params* params, wired_moqtrun_rngrow* rows);
int moqtrun_fsel_up_pass(const wired_moqtrun_fetch* f, const moqfetch_obj* o);
int moqtrun_cut_any(const wired_moqtrun_relay* relay);
int moqtrun_cut_refused(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    usz                  i);
void moqtrun_cut_push(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    wired_moqtrun_relay*       relay);
wired_span moqtrun_cut_skip(
    const wired_moqtrun_relay* relay, usz i, wired_span wire);
void moqtrun_cut_ring_take(
    wired_moqtrun_relay* relay, moqtrel_buf* rb, usz whole_n, u64 now_ms);
void moqtrun_cut_settle(wired_moqtrun_relay* relay, usz whole_n);
int  moqtrun_cut_fin(wired_moqt_hub* hub, wired_moqtrun_relay* relay, int fin);
int moqtrun_cut_torn(wired_moqt_hub* hub, wired_moqtrun_relay* relay, int torn);

#endif
