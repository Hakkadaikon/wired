#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_PART4_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_PART4_H

#include "app/http3/server/srvrun/srvrun_impl_dgring.h"

void srvrun_wt_record_path(srvrun_conn* c, int sidx);
void srvrun_wt_proto_pick(
    const srvrun_cfg* cfg, const srvrun_conn* c, srvrun_wt_proto* p);
void srvrun_wt_seed_limits(const srvrun_conn* c, wired_wt_session* s);
void srvrun_start_wt(
    const srvrun_cfg* cfg, int slot, srvrun_conn* c, srvrun_resp* r);
void srvrun_reject_wt(
    wired_srvrun_env* env, int slot, srvrun_conn* c, srvrun_resp* r);
u8* srvrun_resp_storage(
    const srvrun_step_ctx* ctx, int slot, srvrun_conn* c, srvrun_resp* r);
usz srvrun_resp_storage_cap(const srvrun_resp* r);
u8* srvrun_resp_storage_ro(
    const srvrun_step_ctx* ctx, int slot, srvrun_conn* c, srvrun_resp* r);
usz srvrun_resp_row_size(const srvrun_resp* r);
u8* srvrun_resp_shrink_to_fixed(
    const srvrun_step_ctx* ctx,
    int                    slot,
    srvrun_conn*           c,
    srvrun_resp*           r,
    u8*                    st,
    usz                    total);
void srvrun_arm_hq09_resp(
    const srvrun_conn* c, srvrun_resp* r, u8* st, const wired_obuf* body);
int srvrun_h3_resp_prefix(
    srvrun_conn*               c,
    const wired_http_exchange* x,
    u64                        total_len,
    wired_obuf*                pob);
void srvrun_arm_h3_resp(
    const srvrun_step_ctx*     ctx,
    srvrun_conn*               c,
    int                        slot,
    srvrun_resp*               r,
    u8*                        st,
    const wired_http_exchange* x,
    u64                        total_len);
void srvrun_scratch_view(srvrun_resp* r, usz* off, const u8** p, usz* len);
void srvrun_copy_stream_hdrs(srvrun_resp* r, usz off);
void srvrun_resp_ring_init(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r);
void srvrun_arm_round0(
    const srvrun_step_ctx*     ctx,
    srvrun_conn*               c,
    int                        slot,
    srvrun_resp*               r,
    u8*                        st,
    const wired_http_exchange* x,
    u64                        base_shift);
void srvrun_call_round0(
    const srvrun_step_ctx* ctx, srvrun_conn* c, wired_http_exchange* x);
u64  srvrun_maybe_send_continue(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_start_app_resp(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r);
void srvrun_reject_wt_busy(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r);
void srvrun_dispatch_wt_free_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r);
void srvrun_dispatch_wt(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r);
void srvrun_dispatch_wt_resource(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r);
int  srvrun_wt_settings_ready(const srvrun_conn* c);
int  srvrun_wt_tp_ok(const srvrun_conn* c);
void srvrun_wt_hold(srvrun_conn* c, srvrun_resp* r);
void srvrun_dispatch_wt_gated(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r);
u16  srvrun_method_status(const wired_h3reqdrive_req* r);
void srvrun_start_resp(const srvrun_step_ctx* ctx, int slot);
u8   srvrun_slice_fin(
    const srvrun_conn* c, const srvrun_resp* r, const wired_sendq_slice* sl);
usz srvrun_slice_ack_peek(srvrun_conn* c, const wired_sendq_slice* sl, u8* pl);
int srvrun_seal_send_slice(
    const srvrun_step_ctx* ctx, srvrun_conn* c, wired_span pl, u64 pn, usz al);
int srvrun_send_stream_slice(
    const srvrun_step_ctx*   ctx,
    srvrun_conn*             c,
    wired_sendsess*          sess,
    u64                      stream_id,
    const wired_sendq_slice* sl,
    u8                       fin);
int srvrun_send_taken(
    const srvrun_step_ctx*   ctx,
    srvrun_conn*             c,
    wired_sendsess*          sess,
    u64                      stream_id,
    const wired_sendq_slice* sl,
    u8                       fin);
int srvrun_send_slice(
    const srvrun_step_ctx*   ctx,
    srvrun_conn*             c,
    srvrun_resp*             r,
    const wired_sendq_slice* sl);
usz  srvrun_wtsend_inflight_bytes(const srvrun_conn* c);
usz  srvrun_inflight_bytes_all(const srvrun_conn* c);
int  srvrun_sess_log_room(const wired_sendsess* sess);
usz  srvrun_conn_consumed_bytes(const srvrun_conn* c);
usz  srvrun_sess_consumed(const wired_sendsess* sess);
void srvrun_acct_resync(srvrun_conn* c);
int  srvrun_conn_credit_has_room(const srvrun_conn* c);
int  srvrun_sess_flow_room(
    const srvrun_conn* c, const wired_sendsess* sess, u64 credit);
int srvrun_can_send_new(
    const srvrun_conn* c, const wired_sendsess* sess, u64 credit);
void           srvrun_apply_conn_credit_update(srvrun_conn* c);
int            srvrun_wtsend_matches(const srvrun_wtsend* w, u64 stream_id);
srvrun_wtsend* srvrun_wtsend_find(srvrun_conn* c, u64 stream_id);
void           srvrun_apply_one_stream_credit_update(srvrun_conn* c, usz i);
void           srvrun_apply_stream_credit_update(srvrun_conn* c);
int            srvrun_has_requeued(const wired_sendsess* sess);
void srvrun_notify_conn_blocked(const srvrun_step_ctx* ctx, srvrun_conn* c);
void srvrun_notify_stream_blocked(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    u64                    stream_id,
    const wired_sendsess*  sess,
    u64                    credit,
    srvrun_blocked_mark*   m);
int srvrun_stream_credit_blocked(
    const srvrun_conn* c, const wired_sendsess* sess, u64 credit);
void srvrun_notify_uni_blocked(const srvrun_cfg* cfg, srvrun_conn* c);
int  srvrun_pump_gate_ok(
    const srvrun_conn* c, const wired_sendsess* sess, u64 credit);
int srvrun_pump_one(const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_resp* r);
u8  srvrun_wt_slice_fin(const srvrun_wtsend* w, const wired_sendq_slice* sl);
int srvrun_pump_wt_fin_only(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_wtsend* w);
void srvrun_wtsend_promote_fin_if_ready(const srvrun_conn* c, srvrun_wtsend* w);
int  srvrun_pump_one_wt(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_wtsend* w);
u8   srvrun_wtsend_urgency(const srvrun_wtsend* w);
u32  srvrun_wtsend_key(const srvrun_wtsend* w);
u32  srvrun_wt_pass_key(const srvrun_conn* c);
int  srvrun_wt_flow_ok(const srvrun_conn* c, const srvrun_wtsend* w);
void srvrun_prio_refresh(srvrun_conn* c);
int  srvrun_pump_round(const srvrun_step_ctx* ctx, srvrun_conn* c);
int  srvrun_any_resp_requeued(const srvrun_conn* c);
int  srvrun_any_wtsend_requeued(const srvrun_conn* c);
int  srvrun_pump_round_gated(const srvrun_step_ctx* ctx, srvrun_conn* c);
int  srvrun_pmtu_probe_outstanding(const srvrun_conn* c);
usz  srvrun_pmtu_probe_len(usz size);
void srvrun_pmtu_probe_clear(srvrun_conn* c);
void srvrun_pmtu_note_ack(srvrun_conn* c, usz bytes, u64 hits, u64 hi);
int  srvrun_pmtu_big_lost(
    const srvrun_conn* c, const wired_sendsess_lost_slice* l);
void srvrun_pmtu_feed_losses(srvrun_conn* c, usz big);
int  srvrun_pump_opportunity(const srvrun_step_ctx* ctx, srvrun_conn* c);
void srvrun_pump_sess(const srvrun_step_ctx* ctx, int slot);
void srvrun_qlog_lost(
    const srvrun_cfg*                cfg,
    const srvrun_conn*               c,
    u64                              now_ms,
    u64                              stream_id,
    const wired_sendsess_lost_slice* lost,
    usz                              n);
void srvrun_rtt_note(srvrun_conn* c, u64 sample_ms);
void srvrun_seed_boot_rtt(srvrun_conn* c, int was_booting, u64 now_ms);

#endif
