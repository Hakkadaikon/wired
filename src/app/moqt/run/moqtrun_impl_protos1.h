#ifndef APP_MOQT_RUN_MOQTRUN_IMPL_PART2_H
#define APP_MOQT_RUN_MOQTRUN_IMPL_PART2_H

#include "app/moqt/run/moqtrun_impl_moqtrun.h"

void moqtrun_subscribe_live(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m);
void moqtrun_fill_opened(wired_moqt_hub* hub, const wired_moqtrun_fetch* f);
wired_moqtrun_sub* moqtrun_hub_sub_by_rid(
    wired_moqt_hub* hub, usz idx, u64 rid, wired_moqtrun_track** t);
void moqtrun_upf_drop(wired_moqt_hub* hub, wired_moqtrun_fetch* f, int io);
void moqtrun_upf_unanswered_refuse(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
int  moqtrun_upf_tick(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
void moqtrun_upf_cancel(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
void moqtrun_fill_waits_tick(wired_moqt_hub* hub, int descending);
void moqtrun_fetch_descend(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, const moqtrun_frange* r);
void moqtrun_upf_go(
    wired_moqt_hub*       hub,
    wired_moqtrun_fetch*  f,
    moqtrun_key           k,
    const moqtrun_frange* r,
    const moqctl_params*  params);
void moqtrun_upf_no_track(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    const moqfetch_req* m,
    moqtrun_key         k);
void moqtrun_upf_budget(wired_moqtrun_fetch* f, int has, u64 ms);
void moqtrun_upf_fill(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, const moqtrun_frange* r);
void moqtrun_close_with(wired_moqt_hub* hub, wired_moqtrun_peer* p, u32 code);
void moqtrun_close_with(wired_moqt_hub* hub, wired_moqtrun_peer* p, u32 code);
void moqtrun_close_with(wired_moqt_hub* hub, wired_moqtrun_peer* p, u32 code);
void moqtrun_sub_done(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_req*   q,
    wired_moqtrun_track* t,
    wired_moqtrun_sub*   s,
    u64                  status);
void moqtrun_update_ns(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_req*   q,
    const moqctl_params* params);
void moqtrun_rp_untry(wired_moqt_hub* hub, const wired_moqtrun_req* q);
int  moqtrun_kvp_next(wired_span props, usz* off, u64* prev, moqkvp* kv);
wired_moqtrun_req* moqtrun_req_free_slot(wired_moqt_hub* hub);
wired_moqtrun_req* moqtrun_req_open(
    wired_moqtrun_req* q, wired_wt_session* s, u64 stream_id);
void moqtrun_dispatch_pub_done(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
void moqtrun_pubdone_sweep(wired_moqt_hub* hub);
void moqtrun_pubdone_flush(wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 rid);
void moqtrun_subgroup_scan(
    wired_span wire, wired_moqtrun_track* t, moqdata_objseq* seq, u64* group);
void moqtrun_rel_tick_all(wired_moqt_hub* hub, u64 now_ms);
void moqtrun_reqs_tick(wired_moqt_hub* hub);
void moqtrun_drain_tick(wired_moqt_hub* hub, u64 now_ms);
void moqtrun_subgroup_scan(
    wired_span wire, wired_moqtrun_track* t, moqdata_objseq* seq, u64* group);
void moqtrun_rx_flag(wired_moqt_hub* hub, int bad);
usz  moqtrun_decode_object_loop(
    wired_moqt_hub*      hub,
    wired_span           data,
    usz*                 off,
    moqdata_objseq*      seq,
    u64                  group,
    wired_moqtrun_track* t);
void moqtrun_relay_open_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    wired_span           wire);
int moqtrun_upf_bind(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin);
void moqtrun_upf_torn_unheld(wired_moqt_hub* hub, const wired_wt_session* s);
int  moqtrun_early_free(const wired_moqtrun_peer* p, usz n);
void moqtrun_early_put(
    wired_moqtrun_peer* p, u64 sid, wired_span data, int fin);
int moqtrun_up_pending_for(
    const wired_moqt_hub* hub, const wired_wt_session* s);
void moqtrun_up_crossed(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, moqtrun_key k);
void moqtrun_early_replay(wired_moqt_hub* hub, wired_moqtrun_peer* p);
void moqtrun_dispatch_other(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);
void moqtrun_dispatch_held(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);
int moqtrun_upf_data(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin);
void moqtrun_up_sync(wired_moqt_hub* hub);
void moqtrun_req_cancel(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_req* q);
int moqtrun_up_rx(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);
int moqtrun_upf_rx(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    u64                 sid,
    wired_span          data,
    int                 fin);
void moqtrun_peer_tracks_ended(wired_moqt_hub* hub, wired_moqtrun_peer* p);
void moqtrun_upf_detach(wired_moqt_hub* hub, const wired_wt_session* s);
void moqtrun_up_on_reset(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 stream_id);
void moqtrun_upf_on_reset(wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 sid);
void moqtrun_upf_done_if(wired_moqt_hub* hub, wired_moqtrun_fetch* f);

wired_moqtrun_peer* moqtrun_find_by_wt(
    wired_moqt_hub* hub, wired_wt_session* s);
wired_moqtrun_peer* moqtrun_alloc(wired_moqt_hub* hub);
void                moqtrun_peer_clear_relays(wired_moqtrun_peer* p);
void                moqtrun_reqs_clear(wired_moqt_hub* hub);
void                moqtrun_rdv_clear(wired_moqt_hub* hub);
void                moqtrun_up_clear(wired_moqt_hub* hub);
usz                 moqtrun_envelope_put(
    wired_mspan buf, u64 type, moqtrun_body_encode_fn body_fn, const void* msg);
void moqtrun_setup_limits(moqctl_setup* s, int ver);
void moqtrun_ctl_open(wired_moqt_hub* hub, wired_moqtrun_peer* p);
void moqtrun_peer_ctl_reset(wired_moqtrun_peer* p);
void moqtrun_req_queue(wired_moqtrun_req* q, wired_span msg);
void moqtrun_queue_reply(wired_moqtrun_peer* p, wired_span msg);
void moqtrun_req_mark_live(wired_moqtrun_peer* p);
wired_moqtrun_ctl_asm* moqtrun_cur_asm(wired_moqtrun_peer* p);
void moqtrun_flush_replies(wired_moqt_io* io, wired_moqtrun_peer* p);
void moqtrun_req_flush(
    wired_moqt_io* io, wired_wt_session* s, wired_moqtrun_req* q);
void moqtrun_flush_cur(wired_moqt_io* io, wired_moqtrun_peer* p);
void moqtrun_queue_request_error(
    wired_moqtrun_peer* p, const moqctl_request_error* in);
void moqtrun_send_request_error_ri(wired_moqtrun_peer* p, u64 code, u64 retry);
void moqtrun_send_request_error(wired_moqtrun_peer* p, u64 code);
moqtrun_key moqtrun_key_of(const moqctl_ftn* f, u8* ns_buf);
moqtrun_key moqtrun_key_name(wired_span name);
int         moqtrun_key_oversized(moqtrun_key k);
void        moqtrun_record_track_key(wired_moqtrun_track* t, moqtrun_key k);
int         moqtrun_bytes_eq(const u8* a, const u8* b, usz n);
int moqtrun_track_name_matches(const wired_moqtrun_track* t, wired_span name);
int moqtrun_ns_eq(const u8* ns, usz ns_len, wired_span k);
int moqtrun_track_key_matches(const wired_moqtrun_track* t, moqtrun_key k);
wired_moqtrun_track* moqtrun_track_slot_for_name(
    wired_moqtrun_peer* p, moqtrun_key k);

#endif
