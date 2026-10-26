#ifndef APP_MOQT_RUN_MOQTRUN_IMPL_PART7_H
#define APP_MOQT_RUN_MOQTRUN_IMPL_PART7_H

#include "app/moqt/run/moqtrun_impl_protos5.h"

void moqtrun_rel_attach_sub(
    moqtrel_buf*               rb,
    const wired_moqtrun_track* track,
    const wired_moqtrun_relay* relay,
    usz                        i,
    u64                        sent,
    u64                        now_ms);
void moqtrun_rel_attach_open(
    moqtrel_buf*               rb,
    const wired_moqtrun_track* track,
    const wired_moqtrun_relay* relay,
    usz                        i,
    u64                        now_ms);
void moqtrun_rel_attach_subs(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay);
int moqtrun_rel_holds_start(
    const wired_moqtrun_relay* relay, const moqtrel_buf* rb);
int moqtrun_rel_late_wanted(
    const wired_moqtrun_track* track,
    const wired_moqtrun_relay* relay,
    const moqtrel_buf*         rb,
    usz                        i);
int moqtrun_rel_replay_ok(
    const wired_moqtrun_sub*   sub,
    const wired_moqtrun_relay* relay,
    const moqtrel_buf*         rb);
void moqtrun_rel_lead(
    moqtrel_sub* c, wired_span wire, usz off, moqdata_objseq seq);
void moqtrun_rel_cut_end(
    wired_moqtrun_relay*     relay,
    moqtrel_sub*             c,
    const wired_moqtrun_sub* sub,
    usz                      i,
    wired_span               wire,
    moqdata_objseq           seq,
    u64                      base);
moqdata_objseq moqtrun_relay_hdr_seq(const wired_moqtrun_relay* relay);
void           moqtrun_rel_replay_open(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    usz                  off);
void moqtrun_rel_replay_cuts(
    wired_moqtrun_relay*     relay,
    moqtrel_sub*             c,
    const wired_moqtrun_sub* sub,
    usz                      i,
    wired_span               body,
    usz                      off,
    moqdata_objseq           seq);
void moqtrun_rel_replay(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u64                  now_ms);
void moqtrun_rel_late_attach_all(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    u64                  now_ms);
int                 moqtrun_rel_sub_open(const moqtrel_buf* rb, usz i);
wired_moqtrun_peer* moqtrun_rel_sub_dst(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* track,
    const moqtrel_buf*         rb,
    usz                        i);
void moqtrun_rel_shed(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u32                  code);
int moqtrun_rel_give_up(
    const wired_moqtrun_track* track,
    const wired_moqtrun_relay* relay,
    const moqtrel_buf*         rb,
    usz                        i,
    u64                        now_ms);
void moqtrun_rel_try_fin(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i);
int moqtrun_rel_budget_wait(wired_moqt_hub* hub, wired_wt_session* wt, usz n);
wired_span moqtrun_rel_next(const moqtrel_buf* rb, usz i);
void       moqtrun_rel_send_span(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    wired_span           span,
    u64                  now_ms);
void moqtrun_rel_drain_sub(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u64                  now_ms);
void moqtrun_rel_maybe_release(wired_moqt_hub* hub, moqtrel_buf* rb);
void moqtrun_rel_return_ring(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, moqtrel_buf* rb);
void moqtrun_rel_drain_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    u64                  now_ms);
void moqtrun_rel_continue(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           whole,
    moqdata_objseq       seq0,
    int                  fin,
    u64                  born_ms);
void moqtrun_rel_tick_all(wired_moqt_hub* hub, u64 now_ms);
void moqtrun_relay_sink(wired_moqtrun_relay* relay, int fin);
void moqtrun_relay_end_poisoned(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    int                  fin);
void moqtrun_relay_continue(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           wire,
    int                  fin);
void moqtrun_relay_open_end_hit(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    u64                  sid,
    wired_moqtrun_relay* relay,
    usz                  i,
    usz                  cut_n,
    usz                  wire_n);
int moqtrun_relay_newer_for(
    const wired_moqtrun_sub* sub, const wired_moqtrun_relay* relay);
void moqtrun_relay_open_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    wired_span           wire);
void moqtrun_relay_open_all(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           wire);
void moqtrun_relay_save_hdr_raw(
    wired_moqtrun_relay* relay, wired_span data, usz off);
void moqtrun_relay_start(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_wt_session*    pub_wt,
    u64                  pub_stream_id,
    wired_span           wire,
    usz                  whole_end);
void moqtrun_cache_obj(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    u64                  group,
    const moqdata_obj*   o);
int moqtrun_past_track_end(const wired_moqtrun_track* t, moqctl_loc l);
int moqtrun_past_group_end(const wired_moqtrun_track* t, moqctl_loc l);
int moqtrun_obj_malformed(const wired_moqtrun_track* t, moqctl_loc l);
usz moqtrun_decode_object_loop(
    wired_moqt_hub*      hub,
    wired_span           data,
    usz*                 off,
    moqdata_objseq*      seq,
    u64                  group,
    wired_moqtrun_track* t);
void moqtrun_subgroup_scan(
    wired_span wire, wired_moqtrun_track* t, moqdata_objseq* seq, u64* group);
wired_moqtrun_track* moqtrun_track_by_alias(
    wired_moqtrun_peer* p, u64 track_alias);
wired_moqtrun_track* moqtrun_decode_fresh_subgroup(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_span          data,
    usz*                whole_end,
    int                 fin);
wired_moqtrun_track* moqtrun_resolve_fresh_stream_track(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_span          data,
    usz*                whole_end,
    int                 fin);
void moqtrun_stream_stop(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 sid, u32 code);
int moqtrun_fetch_hdr_keep(
    wired_moqtrun_peer* p, u64 sid, wired_span data, int fin);
int moqtrun_fresh_fetch_stream(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin);
int  moqtrun_early_alias_unknown(wired_moqtrun_peer* p, wired_span data);
int  moqtrun_early_free(const wired_moqtrun_peer* p, usz n);
void moqtrun_early_put(
    wired_moqtrun_peer* p, u64 sid, wired_span data, int fin);
int moqtrun_early_more(
    wired_moqtrun_peer* p, u64 sid, wired_span data, int fin);
void moqtrun_early_drop(wired_moqtrun_peer* p, u64 sid);
void moqtrun_dispatch_fresh_stream(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);
void moqtrun_early_refetch(wired_moqt_hub* hub, wired_moqtrun_peer* p);
void moqtrun_early_replay(wired_moqt_hub* hub, wired_moqtrun_peer* p);
int  moqtrun_rx_is_own_ctl(const wired_moqtrun_peer* p, u64 sid);
void moqtrun_ctl_gone(wired_moqt_hub* hub, wired_moqtrun_peer* p);
void moqtrun_sess_fault(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, moqsess_event ev);
void moqtrun_ctl_rx(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin);
void moqtrun_ctl_adopt_rx(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin);
int moqtrun_pre_stash(wired_moqtrun_peer* p, u64 sid, wired_span data, int fin);

#endif
