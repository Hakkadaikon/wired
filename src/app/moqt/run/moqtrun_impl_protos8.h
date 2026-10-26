#ifndef APP_MOQT_RUN_MOQTRUN_IMPL_PART9_H
#define APP_MOQT_RUN_MOQTRUN_IMPL_PART9_H

#include "app/moqt/run/moqtrun_impl_protos7.h"

wired_moqtrun_track* moqtrun_pubdone_track_of(wired_moqtrun_peer* p, u64 rid);
int                  moqtrun_pubdone_ready(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t);
void moqtrun_malformed_cancel(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const wired_moqtrun_track* t);
int moqtrun_pubdone_try(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_track* t);
void moqtrun_pubdone_sweep(wired_moqt_hub* hub);
void moqtrun_pubdone_flush(wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 rid);
void moqtrun_pubdone_arm(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* t,
    wired_span           body);
void moqtrun_dispatch_pub_done(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
int moqtrun_goaway_send(
    wired_moqt_hub* hub, wired_wt_session* s, wired_span uri, u64 timeout_ms);
void moqtrun_drain_flush(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 now_ms);
void moqtrun_drain_expire(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 now_ms);
int         moqtrun_drain_due(const wired_moqtrun_peer* p, u64 now_ms);
void        moqtrun_ctl_retry(wired_moqt_hub* hub, wired_moqtrun_peer* p);
void        moqtrun_drain_tick(wired_moqt_hub* hub, u64 now_ms);
moqtrun_key moqtrun_up_key(const wired_moqtrun_up* u);
moqtrun_key moqtrun_up_rdv_key(const wired_moqtrun_rdv* r);
int         moqtrun_up_covers(
    const wired_moqtrun_req* q, const wired_wt_session* s, moqtrun_key k);
void moqtrun_rp_untry(wired_moqt_hub* hub, const wired_moqtrun_req* q);
int  moqtrun_up_peer_usable(const wired_moqtrun_peer* p);
wired_moqtrun_req* moqtrun_up_announcer(
    wired_moqt_hub* hub, const wired_wt_session* s, moqtrun_key k);
wired_moqtrun_up* moqtrun_up_of_key(wired_moqt_hub* hub, moqtrun_key k);
wired_moqtrun_up* moqtrun_up_free_slot(wired_moqt_hub* hub);
wired_moqtrun_up* moqtrun_up_of_stream(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid);
int moqtrun_up_pending_for(
    const wired_moqt_hub* hub, const wired_wt_session* s);
wired_moqtrun_track* moqtrun_up_track(
    wired_moqtrun_peer* pp, const wired_moqtrun_up* u);
int  moqtrun_up_encode_sub(wired_mspan buf, usz* off, const void* m);
void moqtrun_up_store(
    wired_moqtrun_up* u, wired_wt_session* s, u64 sid, u64 rid, moqtrun_key k);
void moqtrun_up_refuse_waiters(wired_moqt_hub* hub, moqtrun_key k, u64 code);
int  moqtrun_up_waiters(wired_moqt_hub* hub, moqtrun_key k);
void moqtrun_up_wait_one(wired_moqt_hub* hub, wired_moqtrun_rdv* r);
void moqtrun_up_reset(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, const wired_moqtrun_up* u);
void moqtrun_up_end(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, wired_moqtrun_up* u);
void moqtrun_up_sync(wired_moqt_hub* hub);
void moqtrun_up_claim(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        pp,
    wired_moqtrun_up*          u,
    const moqctl_subscribe_ok* m);
void moqtrun_up_on_reset(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 stream_id);
void moqtrun_ngr_add(moqctl_params* out, u64 v);
u8   moqtrun_ngr_of(const moqctl_params* params, u64* v);
void moqtrun_ngr_upstream(
    const wired_moqt_hub* hub, moqtrun_key k, moqctl_params* out);
void moqtrun_ngr_relay(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    const moqctl_params*       params);
int moqtrun_up_rx(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);
wired_moqtrun_peer* moqtrun_upf_owner(wired_moqt_hub* hub, moqtrun_key k);
wired_moqtrun_peer* moqtrun_upf_target(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     op,
    const wired_wt_session* s,
    moqtrun_key             k);
void moqtrun_upf_params(
    const moqctl_params* in, int rngf, int desc, moqctl_params* out);
void moqtrun_upf_rl_end(moqctl_rangeloc* rl, moqctl_loc e);
i64  moqtrun_upf_send(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, moqfetch_req* m);
wired_moqtrun_upf_leg* moqtrun_upf_leg_of(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f);
int moqtrun_upf_open(
    wired_moqt_hub*        hub,
    wired_moqtrun_fetch*   f,
    wired_moqtrun_peer*    pp,
    moqtrun_key            k,
    const moqctl_rangeloc* rl,
    const moqctl_params*   params);
void moqtrun_upf_budget(wired_moqtrun_fetch* f, int has, u64 ms);
void moqtrun_upf_budget_of(wired_moqtrun_fetch* f, const moqctl_params* params);
void moqtrun_upf_go(
    wired_moqt_hub*       hub,
    wired_moqtrun_fetch*  f,
    moqtrun_key           k,
    const moqtrun_frange* r,
    const moqctl_params*  params);
void moqtrun_upf_fill(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, const moqtrun_frange* r);
void moqtrun_upf_io_none(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, const wired_moqtrun_fetch* f);
void moqtrun_upf_io_cancel(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, const wired_moqtrun_fetch* f);
void moqtrun_upf_io_fin(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, const wired_moqtrun_fetch* f);
void moqtrun_upf_unhold(wired_moqt_hub* hub, const wired_moqtrun_fetch* f);
void moqtrun_upf_drop(wired_moqt_hub* hub, wired_moqtrun_fetch* f, int io);
int  moqtrun_upf_live(const wired_moqtrun_fetch* f);
int moqtrun_upf_leg_to(const wired_moqtrun_fetch* f, const wired_wt_session* s);
void moqtrun_upf_cancel(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
int  moqtrun_upf_no_window(const wired_moqtrun_fetch* f, int done);
void moqtrun_upf_resume(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, int done, int serve);
int                moqtrun_upf_unanswered(const wired_moqtrun_fetch* f);
wired_moqtrun_req* moqtrun_upf_req(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f, wired_moqtrun_peer** dp);
void moqtrun_upf_say_ok(wired_moqtrun_peer* dp, const void* msg);
void moqtrun_upf_answer(
    wired_moqt_hub*      hub,
    wired_moqtrun_fetch* f,
    moqtrun_upf_say_fn   say,
    const void*          msg);
void moqtrun_upf_unanswered_refuse(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
void moqtrun_upf_failed_with(
    wired_moqt_hub*             hub,
    wired_moqtrun_fetch*        f,
    const moqctl_request_error* e,
    int                         serve);
void moqtrun_upf_failed(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, u64 code, int serve);
void moqtrun_upf_fail(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, int io, u64 code);
moqctl_loc moqtrun_upf_loc(const moqfetch_obj* o);
int        moqtrun_upf_valid(const wired_moqtrun_fetch* f, moqctl_loc l);
u64        moqtrun_upf_eor_of(u64 flags, const moqfetch_seq* s);
u64        moqtrun_upf_flags_of(const moqfetch_obj* o, const moqfetch_seq* s);
int        moqtrun_upf_relay(
    wired_moqt_hub*      hub,
    wired_moqtrun_fetch* f,
    const moqfetch_obj*  o,
    wired_span           pre);
wired_moqtrun_track* moqtrun_upf_track(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f);
int moqtrun_upf_past_end(const wired_moqtrun_fetch* f, moqctl_loc l);
int moqtrun_upf_conflicts(
    wired_moqt_hub*            hub,
    const wired_moqtrun_fetch* f,
    moqctl_loc                 l,
    u64                        len,
    u64                        at,
    wired_span                 part);
void moqtrun_upf_item(
    wired_moqt_hub*      hub,
    wired_moqtrun_fetch* f,
    const moqfetch_obj*  o,
    wired_span           pre);

#endif
