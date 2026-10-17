#ifndef APP_MOQT_RUN_MOQTRUN_IMPL_PART8_H
#define APP_MOQT_RUN_MOQTRUN_IMPL_PART8_H

#include "app/moqt/run/moqtrun_impl_protos6.h"

int moqtrun_fresh_uni_ctl(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin);
int  moqtrun_hold_gate(const wired_moqtrun_peer* p);
usz  moqtrun_hold_rec_len(const wired_moqtrun_peer* p, usz at);
int  moqtrun_hold_has(const wired_moqtrun_peer* p, u64 sid);
void moqtrun_hold_put(wired_moqtrun_peer* p, u64 sid, wired_span data, int fin);
void moqtrun_hold_push(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin);
void moqtrun_hold_replay(wired_moqt_hub* hub, wired_moqtrun_peer* p);
void moqtrun_dispatch_data_stream(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);
int moqtrun_req_is(
    const wired_moqtrun_req* q, const wired_wt_session* s, u64 stream_id);
wired_moqtrun_req* moqtrun_req_find(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 stream_id);
wired_moqtrun_req* moqtrun_req_free_slot(wired_moqt_hub* hub);
int moqtrun_req_stream_ok(const wired_moqt_hub* hub, u64 stream_id);
wired_moqtrun_req* moqtrun_req_open(
    wired_moqtrun_req* q, wired_wt_session* s, u64 stream_id);
int moqtrun_req_owned(const wired_moqtrun_req* q, wired_wt_session* s);
usz moqtrun_req_count(const wired_moqt_hub* hub, wired_wt_session* s);
wired_moqtrun_req* moqtrun_req_admit(
    wired_moqt_hub* hub, wired_wt_session* s, u64 stream_id);
wired_moqtrun_req* moqtrun_req_for(
    wired_moqt_hub* hub, wired_wt_session* s, u64 stream_id, wired_span data);
void moqtrun_req_settle(wired_moqt_io* io, wired_moqtrun_req* q);
void moqtrun_reqs_tick_one(wired_moqt_io* io, wired_moqtrun_req* q);
void moqtrun_reqs_tick(wired_moqt_hub* hub);
void moqtrun_req_check_open(wired_moqt_hub* hub, wired_moqtrun_peer* p);
void moqtrun_req_note_fin(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_req* q, int fin);
void moqtrun_dispatch_bidi_fresh(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);
wired_moqtrun_track* moqtrun_pubst_track(wired_moqt_hub* hub, u64 tag);
void                 moqtrun_pubst_open_sub(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_req*   q,
    wired_moqtrun_track* t,
    wired_moqtrun_sub*   s,
    wired_span           body);
int moqtrun_pubst_repeat(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_req* q);
void moqtrun_pubst_update(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_req*  q,
    wired_span          body);
moqtrun_pubst_fn moqtrun_pubst_lookup(u64 type);
void             moqtrun_pubst_recv(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_req*  q,
    wired_span          data);
void moqtrun_dispatch_other(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);
int  moqtrun_rx_on_ctl(const wired_moqtrun_peer* p, u64 sid);
void moqtrun_rx_route(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);
void moqtrun_pre_feed(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin);
void moqtrun_dispatch_held(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);
int  moqtrun_dg_ready(const wired_moqt_hub* hub, const void* p);
int  moqtrun_kvp_next(wired_span props, usz* off, u64* prev, moqkvp* kv);
int  moqtrun_props_have_timeout(wired_span props);
void moqtrun_relays_clear_sub(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz si);
int  moqtrun_sub_is_req(const wired_moqtrun_sub* sub, usz idx, u64 rid);
void moqtrun_each_track(
    wired_moqt_hub* hub, moqtrun_track_fn fn, usz idx, u64 arg);
void moqtrun_drop_peer_subs(wired_moqt_hub* hub, usz idx, u64 rid);
void moqtrun_sub_names_forget(wired_moqtrun_peer* p, u64 rid);
int  moqtrun_track_is_req(const wired_moqtrun_track* t, u64 rid);
void moqtrun_req_cancel(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_req* q);
int moqtrun_encode_publish_done(wired_mspan buf, usz* off, const void* m);
int moqtrun_req_sub_of(
    const wired_moqtrun_req* q, const wired_moqtrun_peer* p, u64 rid);
wired_moqtrun_req* moqtrun_sub_req(
    wired_moqt_hub* hub, const wired_moqtrun_peer* p, u64 rid);
u32  moqtrun_done_reset_code(u64 status);
void moqtrun_sub_reset_streams(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz si, u32 code);
void moqtrun_sub_stop(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    wired_moqtrun_sub*   s,
    u32                  code);
void moqtrun_done_emit(
    wired_moqtrun_peer* p, wired_moqtrun_req* q, u64 status, u64 count);
void moqtrun_done_send(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_req*  q,
    u64                 rid,
    u64                 status,
    u64                 count);
void moqtrun_sub_done(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_req*   q,
    wired_moqtrun_track* t,
    wired_moqtrun_sub*   s,
    u64                  status);
int moqtrun_done_due(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_fetch* f,
    const wired_moqtrun_req*   q);
wired_moqtrun_req* moqtrun_fill_owner_req(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f);
void moqtrun_fill_opened(wired_moqt_hub* hub, const wired_moqtrun_fetch* f);
wired_moqtrun_req* moqtrun_sub_slot_req(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, usz si);
void moqtrun_sub_done_slot(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz si, u64 status);
const moqtsw_ops* moqtrun_sw_ops(void);
u64               moqtrun_rp_bit(wired_moqt_hub* hub, wired_wt_session* s);
u64               moqtrun_rp_skip(wired_moqt_hub* hub, moqtrun_key k);
u64               moqtrun_rp_waiters(wired_moqt_hub* hub, moqtrun_key k);
void moqtrun_rp_mark(wired_moqt_hub* hub, moqtrun_key k, wired_wt_session* s);
u64  moqtrun_rp_status(const wired_moqtrun_track* t);
wired_moqtrun_up* moqtrun_up_of_track(
    wired_moqt_hub* hub, const wired_moqtrun_track* t);
void moqtrun_rp_keep_count(wired_moqt_hub* hub, const wired_moqtrun_sub* s);
int  moqtrun_rp_wait(
    wired_moqt_hub*         hub,
    wired_moqtrun_track*    t,
    usz                     si,
    const wired_moqtrun_up* u,
    u64                     status);
void moqtrun_rp_do_done(
    wired_moqt_hub*          hub,
    wired_moqtrun_peer*      sp,
    const wired_moqtrun_rdv* r,
    wired_moqtrun_track*     t,
    u64                      code);
void moqtrun_rp_flush(wired_moqt_hub* hub, const wired_moqtrun_peer* p);
void moqtrun_rp_do_relinked(
    wired_moqt_hub*          hub,
    wired_moqtrun_peer*      sp,
    const wired_moqtrun_rdv* r,
    wired_moqtrun_track*     t,
    u64                      code);
void moqtrun_track_ended(wired_moqt_hub* hub, wired_moqtrun_track* t);
void moqtrun_peer_tracks_ended(wired_moqt_hub* hub, wired_moqtrun_peer* p);

#endif
