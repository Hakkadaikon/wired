#ifndef APP_MOQT_RUN_MOQTRUN_IMPL_PART4_H
#define APP_MOQT_RUN_MOQTRUN_IMPL_PART4_H

#include "app/moqt/run/moqtrun_impl_protos2.h"

void moqtrun_blob_send_first(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m);
int moqtrun_sub_held_reply(
    wired_moqtrun_peer*        p,
    const wired_moqtrun_track* t,
    const wired_moqtrun_sub*   held);
void moqtrun_subscribe_blob(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m);
void moqtrun_subscribe_peer_track(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    wired_moqtrun_track*    track,
    usz                     peer_idx,
    moqtrun_key             k,
    const moqctl_subscribe* m);
u64 moqtrun_rdv_rt(const moqctl_subscribe* m);
int moqtrun_rdv_holdable(
    wired_moqt_hub*           hub,
    const wired_moqtrun_peer* p,
    const moqctl_subscribe*   m,
    moqtrun_key               k);
wired_moqtrun_rdv* moqtrun_rdv_free_slot(wired_moqt_hub* hub);
int moqtrun_rdv_owned(const wired_moqtrun_rdv* r, const wired_wt_session* s);
wired_moqtrun_rdv* moqtrun_rdv_admit(
    wired_moqt_hub* hub, const wired_wt_session* s);
void moqtrun_rdv_miss(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    const moqctl_subscribe* m,
    moqtrun_key             k,
    wired_span              body);
int moqtrun_rdv_matches(const wired_moqtrun_rdv* r, moqtrun_key k);
int moqtrun_rdv_peer_open(const wired_moqtrun_peer* sp);
wired_moqtrun_req* moqtrun_rdv_target(
    wired_moqt_hub* hub, const wired_moqtrun_rdv* r, wired_moqtrun_peer** sp);
void moqtrun_rdv_answer(
    wired_moqt_hub*      hub,
    wired_moqtrun_rdv*   r,
    moqtrun_rdv_fn       fn,
    wired_moqtrun_track* t,
    u64                  code);
void moqtrun_rdv_do_refuse(
    wired_moqt_hub*          hub,
    wired_moqtrun_peer*      sp,
    const wired_moqtrun_rdv* r,
    wired_moqtrun_track*     t,
    u64                      code);
void moqtrun_rdv_resolve(
    wired_moqt_hub* hub, wired_moqtrun_track* t, moqtrun_key k);
void moqtrun_rdv_tick(wired_moqt_hub* hub, u64 now_ms);
void moqtrun_rdv_drop_stream(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 stream_id);
void moqtrun_rdv_drop_wt(wired_moqt_hub* hub, const wired_wt_session* s);
void moqtrun_rdv_settle_early(wired_moqt_hub* hub, wired_moqtrun_peer* p);
void moqtrun_route_subscribe(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m,
    wired_span              body);
int moqtrun_ns_reserved(const moqctl_ns* ns);
int moqtrun_subscribe_refused(
    const wired_moqt_hub* hub, const moqctl_subscribe* m, u64* code);
int moqtrun_publish_auth_refused(
    const wired_moqt_hub* hub, const moqctl_publish* m, u64* code);
int moqtrun_publish_refused(
    const wired_moqt_hub* hub, const moqctl_publish* m, u64* code);
usz moqtrun_rngf_count(const moqctl_params* params);
u64 moqtrun_rngf_refusal(const moqctl_params* params);
int moqtrun_rngf_rows_over(
    const wired_moqtrun_rngrow* rows, usz n, const moqctl_params* params);
int moqtrun_rngf_over(const wired_moqtrun_sub* s, const moqctl_params* params);
u64 moqtrun_params_refusal(const moqctl_params* params);
u64 moqtrun_subscribe_refusal(
    const wired_moqt_hub* hub, const moqctl_subscribe* m);
void moqtrun_handle_subscribe(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
u8             moqtrun_sub_prio(const wired_moqtrun_sub* s);
u64            moqtrun_flow_of(usz idx, u64 rid);
u64            moqtrun_group_rank(int descending, u64 g);
wired_wt_sched moqtrun_sched_of(
    u8 sub_prio, u8 pub_prio, u64 flow, u64 order, u64 tie);
wired_wt_sched moqtrun_sub_key(
    const wired_moqtrun_sub* s, u8 pub_prio, u64 group, u64 sg);
void moqtrun_sched_apply(
    wired_moqt_hub*       hub,
    wired_wt_session*     wt,
    i64                   sid,
    const wired_wt_sched* k);
moqctl_loc           moqtrun_after(moqctl_loc l);
moqctl_loc           moqtrun_end_excl(moqctl_loc incl);
int                  moqtrun_fetch_live(const wired_moqtrun_fetch* f);
wired_moqtrun_fetch* moqtrun_fetch_arr_slot(wired_moqtrun_fetch* arr);
wired_moqtrun_fetch* moqtrun_fetch_slot(wired_moqt_hub* hub);
int                  moqtrun_fetch_done(const wired_moqtrun_fetch* f);
void moqtrun_fetch_sched(wired_moqt_hub* hub, const wired_moqtrun_fetch* f);
void moqtrun_fetch_free(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
int  moqtrun_fetch_open(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
int  moqtrun_fetch_new_group(const moqfetch_seq* s, u64 group);
void moqtrun_fetch_obj_of(
    moqfetch_obj* o, const moqcache_item* it, const moqfetch_seq* s, u64 eor);
int  moqtrun_fwin_drained(const moqtrun_fwin* w);
u64  moqtrun_fwin_group(const moqtrun_fwin* w);
void moqtrun_fetch_after(
    wired_moqt_hub*            hub,
    const wired_moqtrun_fetch* f,
    moqctl_loc                 from,
    moqtrun_fwin*              w);
usz moqtrun_fetch_encode_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_fetch* f,
    moqfetch_seq*        seq,
    moqctl_loc*          next);
void moqtrun_fetch_advance(
    wired_moqt_hub*      hub,
    wired_moqtrun_fetch* f,
    moqfetch_seq         seq,
    const moqtrun_fwin*  w);
void moqtrun_fetch_serve(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
void moqtrun_fetch_stop_code(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, u32 code);
void moqtrun_fetch_stop(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
int  moqtrun_fetch_owned(
    const wired_moqtrun_fetch* f, const wired_wt_session* s);
int moqtrun_fill_held_for(
    const wired_moqt_hub* hub, const wired_wt_session* s, u64 rid);
int  moqtrun_fetch_fail_due(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
void moqtrun_fetch_tick_one(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
void moqtrun_fills_upstream_gone(wired_moqt_hub* hub, u64 tag);
int  moqtrun_fetch_in_pass(const wired_moqtrun_fetch* f, int descending);
void moqtrun_fetches_tick(wired_moqt_hub* hub, int descending);
void moqtrun_fetches_cancel(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 rid);
void moqtrun_fetches_stream_gone(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid);
void moqtrun_queue_fetch_ok_m(wired_moqtrun_peer* p, const moqfetch_ok* ok);
void moqtrun_queue_fetch_ok(
    wired_moqtrun_peer* p, moqctl_loc end, wired_span props);
moqctl_loc           moqtrun_fetch_last(moqcache* c, const moqtrun_frange* r);
wired_moqtrun_fetch* moqtrun_fetch_begin(
    wired_moqt_hub*       hub,
    wired_wt_session*     wt,
    u64                   request_id,
    const moqtrun_frange* r);
int                  moqtrun_fetch_order_desc(const moqctl_params* params);
wired_moqtrun_fetch* moqtrun_fetch_accept(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    u64                   request_id,
    const moqtrun_frange* r,
    int                   descending);
void moqtrun_fetch_start(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
int  moqtrun_fetch_resolve(
    const wired_moqtrun_track* t, const moqctl_rangeloc* rl, moqtrun_frange* r);
void moqtrun_fetch_standalone(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqfetch_req* m);
void moqtrun_fetch_descend(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, const moqtrun_frange* r);
void moqtrun_fill_flag(
    wired_moqt_hub*       hub,
    wired_moqtrun_fetch*  f,
    u64                   owner_rid,
    int                   descending,
    const moqtrun_frange* r);
void moqtrun_fill_waits_tick(wired_moqt_hub* hub, int descending);

#endif
