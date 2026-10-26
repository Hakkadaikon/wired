#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_DGRING_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_DGRING_H

#include "app/http3/server/srvrun/srvrun_impl_protos2.h"

srvrun_conn* srvrun_session_conn_env(
    wired_wt_session* s, wired_srvrun_env** env_out, int* slot_out);
srvrun_conn*   srvrun_session_conn(wired_wt_session* s);
srvrun_wtsend* srvrun_wtsend_take(srvrun_wtsend* w, u64 credit);
srvrun_wtsend* srvrun_wtsend_claim(srvrun_conn* c, u64 credit);
u64            srvrun_next_uni_id(srvrun_conn* c);
u64            srvrun_peer_uni_limit(const srvrun_conn* c);
void           srvrun_apply_uni_limit_update(srvrun_conn* c);
u64            srvrun_uni_plumbing(const srvrun_conn* c);
int            srvrun_uni_open_allowed(const srvrun_conn* c);
u64            srvrun_next_bidi_id(srvrun_conn* c);
i64            srvrun_wtsend_arm_id(
    const srvrun_conn* c, srvrun_wtsend* w, u64 id, wired_span payload);
void           srvrun_open_qenc_stream(srvrun_conn* c);
int            srvrun_qdec_open_due(const srvrun_conn* c);
void           srvrun_open_qpack_streams(srvrun_conn* c);
srvrun_wtsend* srvrun_plumbing_wtsend(
    srvrun_conn* c, int opened, int slot, u64 stream_id);
void srvrun_flush_qdec(srvrun_conn* c);
int  srvrun_wt_session_slot_or_absent(srvrun_conn* c, wired_wt_session* s);
int  srvrun_wt_open_flow_ok(
    int sidx, wired_wt_session* s, int bidi, wired_span payload);
void srvrun_wt_notify_streams_blocked(
    srvrun_conn* c, int sidx, const wired_wt_session* s, int bidi);
int srvrun_wt_uni_grant_ok(srvrun_conn* c);
int srvrun_wt_uni_open_ok(
    srvrun_conn* c, int sidx, wired_wt_session* s, wired_span payload);
i64 srvrun_wt_open_uni_common(
    wired_wt_session* s, wired_span payload, int keep_open);
int            srvrun_wt_reply_flow_ok(int sidx, wired_wt_session* s, usz len);
int            srvrun_wt_rx_owner(const srvrun_conn* c, u64 stream_id);
int            srvrun_wt_foreign(srvrun_conn* c, int sidx, u64 stream_id);
int            srvrun_wt_rx_owns(const srvrun_conn* c, int sidx, u64 stream_id);
srvrun_wtsend* srvrun_wtsend_owned(srvrun_conn* c, int sidx, u64 stream_id);
int            srvrun_wtsend_open_slot(const srvrun_wtsend* w);
int            srvrun_wtsend_epoch_acked(const srvrun_wtsend* w);
int            srvrun_wtsend_closing(const srvrun_wtsend* w);
int            srvrun_wtsend_appendable(const srvrun_wtsend* w, usz len);
void srvrun_wtsend_epoch_reset(const srvrun_conn* c, srvrun_wtsend* w);
int  srvrun_wtsend_stage_round(
    const srvrun_conn* c, srvrun_wtsend* w, wired_span payload, int fin);
int srvrun_wtsend_accept_round(
    const srvrun_conn* c, srvrun_wtsend* w, wired_span payload, int fin);
srvrun_wtsend* srvrun_wt_connect_sender(srvrun_conn* c, int sidx);
int            srvrun_send_wt_capsule(
    srvrun_conn* c, int sidx, wired_span capsule_bytes, u8 fin);
int  srvrun_wt_connect_finable(const srvrun_wtsend* w);
void srvrun_wt_connect_sender_drop(srvrun_conn* c, int sidx);
int  srvrun_wtsend_busy_reject(const srvrun_wtsend* w, usz len);
int  srvrun_wtsend_flow_refuse(srvrun_conn* c);
void srvrun_wtsend_start_fin_now(const srvrun_conn* c, srvrun_wtsend* w);
void srvrun_wtsend_request_fin(const srvrun_conn* c, srvrun_wtsend* w);
void srvrun_wt_connect_fin(srvrun_conn* c, int sidx);
srvrun_wtsend* srvrun_wtsend_of(wired_wt_session* s, u64 stream_id);
void           srvrun_wtsend_release(srvrun_conn* c, u64 stream_id);
u64            srvrun_wtsend_final_size(srvrun_conn* c, u64 stream_id);
int            srvrun_wt_send_ended(srvrun_conn* c, u64 stream_id);
void           srvrun_wt_send_done_mark(srvrun_conn* c, u64 stream_id);
int            srvrun_wt_stop_refused(srvrun_conn* c, int sidx, u64 stream_id);
int            srvrun_bcast_ring_sess(
    wired_srvrun_env* env, int cslot, int i, wired_span data);
void srvrun_dgring_send_one(
    const srvrun_cfg* cfg, srvrun_state* st, const srvrun_dgring_entry* e);
/* RFC 9221 5.1: send the most urgent unsent ring entry if it fits the
 * slice's byte budget (*bytes, the slice's total so far); 0 when none was
 * sent. */
int srvrun_dgring_send_best(
    const srvrun_cfg* cfg, srvrun_state* st, usz* bytes);
void srvrun_dgring_drain(const srvrun_cfg* cfg, srvrun_state* st, u64 now_ms);
void srvrun_goaway_all(const srvrun_cfg* cfg, srvrun_state* st);
int  srvrun_all_drained(const srvrun_state* st);
void srvrun_sigterm_handler(int sig);
int  srvrun_shutdown_requested(void);
__attribute__((unused)) static void srvrun_test_set_shutdown(int v);
void                                srvrun_sighup_handler(int sig);
void srvrun_reload_if_requested(const srvrun_cfg* cfg, wired_srvrun_env* env);
int  srvrun_is_new(const srvrun_conn* c, wired_mspan dg);
int  srvrun_awaiting_confirm(const srvrun_conn* c);
int  srvrun_hrr_pending(const srvrun_conn* c);
int  srvrun_boot_probe_armed(const srvrun_conn* c);
int  srvrun_is_boot_retransmit(const srvrun_conn* c, wired_mspan dg);
void srvrun_free_bigbuf_rows(wired_srvrun_env* env, srvrun_conn* c);
void srvrun_close_all_wt(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_free_slot(const srvrun_cfg* cfg, srvrun_state* st, int i);
int  srvrun_slot_busy(const srvrun_conn* c);
int  srvrun_boot_overdue(const srvrun_conn* c, u64 now_ms);
int  srvrun_close_reap_due(const srvrun_conn* c, u64 now_ms);
int  srvrun_reap_due(const srvrun_conn* c, u64 now_ms);
void srvrun_sweep_idle(const srvrun_cfg* cfg, srvrun_state* st, u64 now_ms);
void srvrun_open_done(const srvrun_step_ctx* ctx, int slot, int ok);
void srvrun_call_handler(const srvrun_step_ctx* ctx, wired_http_exchange* x);
int  srvrun_http_status_final(u16 status);
int  srvrun_http_status_bodiless(u16 status);
int  srvrun_http_fields_ok(const wired_http_exchange* x);
int  srvrun_http_ct_ok(const char* ct);
u16  srvrun_http_status(const wired_http_exchange* x);
void srvrun_http_settle(wired_http_exchange* x);
int  srvrun_wt_bytes_eq(const u8* m, const u8* want, usz len);
int  srvrun_is_wt_connect(const wired_h3reqdrive_req* r);
int  srvrun_is_wt_connect_unsupported_protocol(const wired_h3reqdrive_req* r);
int  srvrun_wt_origin_ok(const srvrun_cfg* cfg, const wired_h3reqdrive_req* r);
int  srvrun_wt_request_ok(const wired_h3reqdrive_req* r);
int  srvrun_wt_protocol_is_h3(const wired_h3reqdrive_req* r);
int  srvrun_h3_datagram_ok(const srvrun_conn* c);
int  srvrun_wt_peer_ok(const srvrun_conn* c);
void srvrun_reject_wt_malformed(
    const srvrun_cfg* cfg, srvrun_conn* c, srvrun_resp* r);
srvrun_resp* srvrun_resp_find(srvrun_conn* c, u64 stream_id);
srvrun_resp* srvrun_resp_claim(srvrun_conn* c, u64 stream_id);
usz          srvrun_resp_index(const srvrun_conn* c, const srvrun_resp* r);
void         srvrun_start_wt_status(
    wired_srvrun_env*  env,
    int                slot,
    srvrun_conn*       c,
    srvrun_resp*       r,
    u16                status,
    const qpack_field* extra);
void srvrun_reject_wt_redirect(
    wired_srvrun_env* env,
    int               slot,
    srvrun_conn*      c,
    srvrun_resp*      r,
    u16               status,
    wired_span        location);
void srvrun_wt_resource_decide(
    const srvrun_cfg*           cfg,
    const srvrun_conn*          c,
    wired_wt_resource_decision* out);
void srvrun_start_wt_resource_status(
    wired_srvrun_env*                 env,
    int                               slot,
    srvrun_conn*                      c,
    srvrun_resp*                      r,
    const wired_wt_resource_decision* d);

#endif
