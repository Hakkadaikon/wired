#ifndef APP_MOQT_RUN_MOQTRUN_IMPL_PART5_H
#define APP_MOQT_RUN_MOQTRUN_IMPL_PART5_H

#include "app/moqt/run/moqtrun_impl_protos3.h"

moqctl_rangeloc moqtrun_fill_rl(
    const moqfetch_fill* fill, const wired_moqtrun_sub* sub);
void moqtrun_fill_open(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    wired_moqtrun_sub*    sub,
    u64                   rid,
    const moqfetch_fill*  fill,
    const moqtrun_frange* r);
int moqtrun_fill_room(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* track,
    const wired_moqtrun_sub*   sub,
    const moqctl_params*       params);
int moqtrun_fill_malformed(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_params* params);
void moqtrun_fill_on_subscribe(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* track,
    wired_moqtrun_sub*   sub,
    const moqctl_params* params);
void moqtrun_fill_on_update(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* track,
    wired_moqtrun_sub*   sub,
    const moqctl_params* params,
    u64                  rid);
wired_moqtrun_sub* moqtrun_track_sub_by_rid(
    wired_moqtrun_track* t, usz idx, u64 rid);
wired_moqtrun_sub* moqtrun_live_track_sub_by_rid(
    wired_moqtrun_track* t, usz idx, u64 rid);
wired_moqtrun_sub* moqtrun_sub_by_rid(
    wired_moqt_hub* hub, usz idx, u64 rid, wired_moqtrun_track** t);
int moqtrun_fetch_take(
    const wired_moqtrun_peer* p, wired_span body, moqfetch_req* m);
void moqtrun_fetch_route(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    usz                 peer_idx,
    const moqfetch_req* m);
void moqtrun_handle_fetch(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
void moqtrun_fetches_drop(wired_moqt_hub* hub, wired_wt_session* s);
void moqtrun_handle_tstat(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
wired_moqtrun_sub* moqtrun_hub_sub_by_rid(
    wired_moqt_hub* hub, usz idx, u64 rid, wired_moqtrun_track** t);
wired_moqtrun_sub* moqtrun_sub_state_by_rid(wired_moqtrun_peer* p, u64 rid);
wired_moqtrun_sub* moqtrun_upd_target(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    usz                   idx,
    wired_moqtrun_track** t);
int moqtrun_upd_turned_on(
    u8 was_off, const wired_moqtrun_sub* s, const wired_moqtrun_track* t);
int moqtrun_upd_forward_on(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t);
void moqtrun_upd_params(
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params);
int moqtrun_upd_apply(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params);
int moqtrun_ssts_settable(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_peer*  p,
    const wired_moqtrun_track* t);
void moqtrun_upd_resched(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_track* t);
void moqtrun_upd_remember(wired_moqtrun_peer* p, const wired_moqtrun_sub* s);
void moqtrun_update_sub(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    usz                  idx,
    const moqctl_params* params,
    u64                  rid);
int  moqtrun_kind_is_ns(u64 kind);
void moqtrun_upd_close_ns(wired_moqtrun_req* q);
int  moqtrun_upd_is_sub(const wired_moqtrun_peer* p);
u32  moqtrun_upd_ctx(const wired_moqtrun_peer* p);
void moqtrun_update_route(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    usz                  peer_idx,
    const moqctl_params* params,
    u64                  rid);
void moqtrun_upd_refuse(wired_moqt_hub* hub, wired_moqtrun_peer* p);
int  moqtrun_upd_refused(wired_moqt_hub* hub, wired_moqtrun_peer* p);
void moqtrun_handle_update(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
int        moqtrun_disc_is(const wired_moqtrun_req* q, u64 kind);
wired_span moqtrun_disc_fields_of(wired_span enc, u64* count);
wired_span moqtrun_disc_fields(const wired_moqtrun_req* q, u64* count);
int        moqtrun_disc_starts(wired_span pre, wired_span all);
int        moqtrun_disc_under(
    const wired_moqtrun_req* sub, const wired_moqtrun_req* pub);
int moqtrun_disc_overlap(
    const wired_moqtrun_req* a, const wired_moqtrun_req* b);
int moqtrun_disc_same(const wired_moqtrun_req* a, const wired_moqtrun_req* b);
int moqtrun_disc_any(
    const wired_moqt_hub*    hub,
    const wired_moqtrun_req* q,
    u64                      kind,
    moqtrun_disc_rel_fn      rel);
u64 moqtrun_disc_pub_check(
    const wired_moqt_hub* hub, const wired_moqtrun_req* q);
u64 moqtrun_disc_sub_check(
    const wired_moqt_hub* hub, const wired_moqtrun_req* q);
void moqtrun_update_ns(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_req*   q,
    const moqctl_params* params);
u64 moqtrun_disc_verdict(
    const wired_moqt_hub* hub,
    wired_moqtrun_req*    q,
    const moqns_req*      m,
    moqtrun_disc_check_fn check);
void moqtrun_disc_answer(wired_moqtrun_peer* p, u64 err);
void moqtrun_dispatch_publish_ns(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
void moqtrun_dispatch_subscribe_ns(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
int moqtrun_disc_push(
    wired_moqtrun_req* sub, const wired_moqtrun_req* pub, u64 type);
u64 moqtrun_disc_bit(usz i);
usz moqtrun_disc_word(usz i);
int moqtrun_disc_seen(const wired_moqtrun_req* sub, usz i);
int moqtrun_disc_fresh(
    const wired_moqt_hub*    hub,
    const wired_moqtrun_req* sub,
    const wired_moqtrun_req* q);
void moqtrun_disc_sync_new(wired_moqt_hub* hub, wired_moqtrun_req* sub, usz i);
void moqtrun_disc_sync(wired_moqt_hub* hub);
int  moqtrun_disc_held(const wired_moqt_hub* hub, usz i);
void moqtrun_handle_not_supported(wired_moqtrun_peer* p);
u64  moqtrun_subtracks_check(
    const wired_moqt_hub* hub, const wired_moqtrun_req* q);
void moqtrun_subtracks_rngf_item(wired_moqtrun_req* q, const moqctl_param* it);
void moqtrun_rngf_copy_objects(
    wired_moqtrun_req* q, const wired_moqtrun_req* st);
int moqtrun_subtracks_tp_pass(
    const wired_moqtrun_req* st, const wired_moqtrun_track* t);
void moqtrun_subtracks_admit(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqns_req* m);
void moqtrun_dispatch_subscribe_tracks(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
usz  moqtrun_subtracks_slot(usz peer_idx, usz track_idx);
void moqtrun_subtracks_mark_tried(
    wired_moqtrun_req* st, const wired_moqtrun_track* t, usz slot);
int moqtrun_subtracks_candidate(
    const wired_moqtrun_req*   st,
    const wired_moqtrun_track* t,
    usz                        pub_idx,
    usz                        st_peer_idx,
    usz                        slot);
moqctl_params moqtrun_subtracks_publish_params(const wired_moqtrun_req* st);
wired_moqtrun_req* moqtrun_subtracks_claim_slot(
    wired_moqt_hub* hub, wired_moqtrun_peer* st_peer, u64 st_rid);
int moqtrun_subtracks_open_pub(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        st_peer,
    wired_moqtrun_req*         q,
    const wired_moqtrun_track* t,
    const wired_moqtrun_req*   st);
int moqtrun_subtracks_encode_skip(wired_mspan buf, usz* off, const void* m);

#endif
