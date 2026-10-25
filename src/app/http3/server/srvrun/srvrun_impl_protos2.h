#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_PART3_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_PART3_H

#include "app/http3/server/srvrun/srvrun_impl_wt.h"

void srvrun_grant_wt_slot_credit(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_srvloop_wt_stream_slot* slot);
void srvrun_grant_wt_uni_slot_credit(
    const srvrun_cfg*                 cfg,
    srvrun_conn*                      c,
    wired_srvloop_wt_uni_stream_slot* slot);
u64 srvrun_wt_rx_delivered_total(const srvrun_conn* c);
int srvrun_seal_path_frames(
    srvrun_conn* c,
    wired_span   dcid,
    u8           type,
    const u8*    data,
    usz          n,
    wired_obuf*  out);
int  srvrun_seal_max_data(srvrun_conn* c, u64 value, wired_obuf* out);
void srvrun_send_max_data(const srvrun_cfg* cfg, srvrun_conn* c, u64 value);
void srvrun_send_data_blocked(const srvrun_cfg* cfg, srvrun_conn* c, u64 limit);
void srvrun_send_stream_data_blocked(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id, u64 limit);
int srvrun_seal_max_streams(
    srvrun_conn* c, int uni, u64 value, wired_obuf* out);
void srvrun_send_streams_blocked(
    const srvrun_cfg* cfg, srvrun_conn* c, int uni, u64 limit);
void srvrun_grant_streams(
    const srvrun_step_ctx* ctx, srvrun_conn* c, u64 base, usz n);
void srvrun_grant_retry_slot(const srvrun_step_ctx* ctx, int slot);
void srvrun_grant_uni_streams(const srvrun_cfg* cfg, srvrun_conn* c, usz n);
void srvrun_reannounce_stream_limit(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 base);
void srvrun_reannounce_uni_stream_limit(const srvrun_cfg* cfg, srvrun_conn* c);
int  srvrun_wt_any_slot_in_use(const srvrun_conn* c);
usz  srvrun_wt_bidi_slots_in_use(const srvrun_conn* c);
usz  srvrun_wt_uni_slots_in_use(const srvrun_conn* c);
int  srvrun_req_credit_live(const wired_srvloop_stream_slot* slot);
u64  srvrun_req_rx_ceiling(const srvrun_conn* c);
void srvrun_grant_conn_credit(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_grant_qenc_credit(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_grant_wt_credit(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_grant_body_credit(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_srvloop_stream_slot* slot);
void srvrun_grant_req_credit(const srvrun_cfg* cfg, srvrun_conn* c);
int  srvrun_wt_connect_stream_slot(const srvrun_conn* c);
void srvrun_reset_wt_sends_for_session(
    const srvrun_cfg* cfg, srvrun_conn* c, int session_slot, u64 err_code);
void srvrun_reset_wt_streams_for_session(
    const srvrun_cfg* cfg, srvrun_conn* c, int session_slot, u64 err_code);
void srvrun_notify_wt_close(const srvrun_cfg* cfg, wired_wt_session* s);
void srvrun_close_wt_session_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, u64 err_code);
const wired_srvloop_stream_slot* srvrun_req_slot_of(
    const srvrun_conn* c, u64 id);
wired_srvloop_stream_slot* srvrun_wt_rx_slot(srvrun_conn* c, int sidx);
usz                        srvrun_wt_capsule_start(const srvrun_conn* c);
int                        srvrun_wt_capsule_flow_type(u64 type);
int                        srvrun_wt_capsule_streams_blocked_type(u64 type);
int                        srvrun_wt_capsule_is_flow_control(u64 type);
int srvrun_wt_capsule_close(srvrun_wt_caprx* x, wired_span value);
int srvrun_wt_capsule_streams_blocked(srvrun_wt_caprx* x, wired_span value);
int srvrun_wt_capsule_flow_raise(
    srvrun_wt_caprx* x, u64 type, wired_span value);
int srvrun_wt_rx_walk(
    const srvrun_cfg*          cfg,
    srvrun_conn*               c,
    int                        sidx,
    wired_srvloop_stream_slot* slot,
    srvrun_wt_caprx*           out);
void srvrun_reset_connect_stream_code(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, u64 code);
void srvrun_wt_rx_fail(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, u64 code);
void srvrun_wt_rx_capsules_one(const srvrun_cfg* cfg, srvrun_conn* c, int sidx);
void srvrun_wt_rx_capsules(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_close_wt_on_stream_close(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_send_wt_close(const srvrun_cfg* cfg, srvrun_conn* c, int sidx);
void srvrun_raw_close(const srvrun_cfg* cfg, srvrun_conn* c, int sidx);
void srvrun_drain_wt_close_pending(const srvrun_cfg* cfg, srvrun_conn* c);
int  srvrun_seal_wt_stream_reset(srvrun_conn* c, usz i, wired_obuf* out);
void srvrun_drain_wt_stream_reset(const srvrun_cfg* cfg, srvrun_conn* c);
int  srvrun_wt_reset_bidi_matches(
    const wired_srvloop_wt_stream_slot* slot, u64 reset_stream_id);
void srvrun_deliver_wt_reset(
    const srvrun_cfg*          cfg,
    srvrun_conn*               c,
    int                        sidx,
    const wired_srvloop_reset* e);
usz  srvrun_peer_resets_stored(const srvrun_conn* c);
void srvrun_deliver_wt_reset_if_owned(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_close_on_datagram_violation(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_close_on_wt_signal_violation(const srvrun_cfg* cfg, srvrun_conn* c);
int  srvrun_close_on_frame_error(const srvrun_cfg* cfg, srvrun_conn* c);
int  srvrun_flow_violated(const srvrun_conn* c);
int  srvrun_close_on_cid(const srvrun_cfg* cfg, srvrun_conn* c);
int  srvrun_close_on_limits(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_roll_reset_window(srvrun_conn* c, u64 now_ms);
int  srvrun_close_on_step_violation(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_send_step_reply(
    const srvrun_cfg* cfg, srvrun_conn* c, int produced, wired_span out);
void srvrun_ku_note_rotation(srvrun_conn* c, u64 now_ms);
void srvrun_refuse_wt_streams(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_grant_wt_streams(const srvrun_step_ctx* ctx, srvrun_conn* c);
int  srvrun_raw_start_due(const srvrun_conn* c);
void srvrun_raw_notify(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_on_step_live(
    const srvrun_step_ctx* ctx, srvrun_conn* c, wired_mspan dg);
void srvrun_closing_rx(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_on_step(const srvrun_step_ctx* ctx, srvrun_conn* c, wired_mspan dg);
int  srvrun_send_goaway(const srvrun_cfg* cfg, srvrun_conn* c, wired_obuf* out);
void srvrun_send_wt_drain_all(srvrun_conn* c);
void srvrun_flush_wt_drain(srvrun_conn* c);
int  srvrun_owes_goaway(const srvrun_conn* c);
int  srvrun_queue_datagram(srvrun_conn* c, wired_span data);
int  srvrun_send_datagram_now(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_span data, wired_obuf* out);
int srvrun_send_pending_datagram(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_obuf* out);
int               srvrun_wt_any_active(const srvrun_conn* c);
void              srvrun_broadcast_to_all(srvrun_state* st, wired_span data);
int               srvrun_bcast_find(i64 tid);
int               srvrun_broadcast_direct(wired_span data);
int               srvrun_broadcast_registered(int slot, wired_span data);
void              srvrun_bcast_drain_self(srvrun_state* st);
wired_srvrun_env* srvrun_caller_env(void);
int               srvrun_conn_session_slot(srvrun_conn* c, wired_wt_session* s);

#endif
