#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_WT_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_WT_H

#include "app/http3/server/srvrun/srvrun_impl_wt2.h"

void srvrun_tx(
    const srvrun_cfg* cfg, i64 fd, const sockaddr* sa, wired_span pkt);
int  srvrun_ecn_unmarked(const srvrun_cfg* cfg, const srvrun_conn* c);
void srvrun_send_now(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_span pkt, const char* what);
void srvrun_send(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_span pkt, const char* what);
void srvrun_log_close(const char* what, wired_span reason);
void srvrun_log_close_alert(const char* what, u64 code);
void srvrun_stage_flush(const srvrun_cfg* cfg);
void srvrun_stage_put(
    const srvrun_cfg* cfg, const srvrun_conn* c, wired_span pkt);
void srvrun_send_staged(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_span pkt, const char* what);
int  srvrun_send_spend(const srvrun_cfg* cfg, srvrun_conn* c, usz n);
void srvrun_boot_send(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_span pkt, const char* what);
int srvrun_boot_gate_blocks(const srvrun_conn* c, int confirmed, usz want);
int srvrun_boot_send_initial(
    const srvrun_cfg* cfg, srvrun_conn* c, const char* what);
usz srvrun_boot_send_hs_gated(
    const srvrun_cfg* cfg, srvrun_conn* c, int confirmed);
wired_srvboot_id srvrun_slot_id(
    const wired_srvboot_id* base, const srvrun_conn* c);
int  srvrun_refuse(const srvrun_step_ctx* ctx, srvrun_conn* c);
void srvrun_boot_flush_zerortt(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot);
int srvrun_boot_finish(
    const srvrun_step_ctx* ctx, int slot, srvrun_conn* c, wired_mspan dg);
int srvrun_boot_feed(srvrun_conn* c, wired_mspan dg, u8 ecn);
int srvrun_on_initial(
    const srvrun_step_ctx* ctx, int slot, srvrun_conn* c, wired_mspan dg);
usz srvrun_wt_abort_reset(
    srvrun_conn* c, u64 stream_id, u64 err_code, wired_obuf* plb, usz at);
usz srvrun_wt_abort_stop(
    const srvrun_conn* c, u64 stream_id, u64 err_code, wired_obuf* plb, usz at);
int srvrun_peer_reset_seen(const srvrun_conn* c, u64 stream_id);
usz srvrun_wt_abort_pair(
    srvrun_conn* c, u64 stream_id, u64 err_code, wired_obuf* plb);
usz srvrun_wt_busy_reset_payload(
    srvrun_conn* c, u64 stream_id, u64 err_code, wired_obuf* plb);
int  srvrun_seal_ctl(srvrun_conn* c, const u8* pl, usz pln, wired_obuf* out);
int  srvrun_seal_kept(srvrun_conn* c, const u8* pl, usz pln, wired_obuf* out);
void srvrun_send_kept(
    const srvrun_cfg* cfg,
    srvrun_conn*      c,
    const u8*         pl,
    usz               pln,
    const char*       msg);
void srvrun_send_stop_sending(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id);
void srvrun_rst_send(
    const srvrun_cfg* cfg, srvrun_conn* c, srvrun_rst* e, u64 now_ms);
void srvrun_rst_keep(srvrun_conn* c, const u8* pl, usz pln);
void srvrun_send_wt_busy_reset(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id, u64 err_code);
void srvrun_rst_ack(srvrun_conn* c, u64 lo, u64 hi);
int  srvrun_rst_pending(const srvrun_conn* c);
int  srvrun_wt_app_pending(const srvrun_conn* c);
int  srvrun_rst_retry(const srvrun_cfg* cfg, srvrun_conn* c, u64 now);
usz  srvrun_app_close_payload(
    u64 error_code, wired_span reason, wired_obuf* plb);
int  srvrun_seal_close_pl(srvrun_conn* c, wired_span pl, wired_obuf* out);
void srvrun_close_resend(const srvrun_cfg* cfg, srvrun_conn* c);
int  srvrun_close_send(const srvrun_cfg* cfg, srvrun_conn* c, wired_span pl);
void srvrun_send_app_close(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 error_code, wired_span reason);
usz  srvrun_send_continue(const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id);
void srvrun_send_transport_close(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 error_code, wired_span reason);
wired_wt_session*       srvrun_wt_slot(srvrun_conn* c, int i);
int*                    srvrun_wt_active_slot(srvrun_conn* c, int i);
const wired_wt_session* srvrun_wt_slot_c(const srvrun_conn* c, int i);
int                     srvrun_wt_is_active(const srvrun_conn* c, int i);
int  srvrun_wt_slot_by_connect_id(const srvrun_conn* c, u64 stream_id);
int  srvrun_wt_free_slot(const srvrun_conn* c);
usz  srvrun_wt_active_total(const wired_srvrun_env* env);
int  srvrun_wt_no_room(const srvrun_cfg* cfg, const srvrun_conn* c);
int  srvrun_wt_slot_for_new_stream(const srvrun_conn* c);
int  srvrun_wt_slot_for_signal(const srvrun_conn* c, const u8* sig, u8 have);
int  srvrun_wt_stream_owner(const srvrun_conn* c, int offered, int owner);
void srvrun_wt_bidi_slot_free(
    srvrun_conn* c, wired_srvloop_wt_stream_slot* slot);
void srvrun_wt_uni_slot_free(
    srvrun_conn* c, wired_srvloop_wt_uni_stream_slot* slot);
u64  srvrun_refuse_code(const srvrun_conn* c, u64 h3);
void srvrun_reject_wt_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id);
void srvrun_offer_wt_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_srvloop_wt_stream_slot* slot);
int  srvrun_wt_slot_needs_offer(const wired_srvloop_wt_stream_slot* slot);
void srvrun_deliver_wt_stream_delta(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, const srvrun_wt_rx* rx);
void srvrun_reap_wt_slot(srvrun_conn* c, wired_srvloop_wt_stream_slot* slot);
void srvrun_offer_and_deliver_wt_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_srvloop_wt_stream_slot* slot);
void srvrun_offer_wt_streams(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_close_on_bad_qsid(const srvrun_cfg* cfg, srvrun_conn* c);
int  srvrun_wt_session_send_side_open(const wired_wt_session* s);
void srvrun_deliver_to_known_session(
    const srvrun_cfg* cfg, wired_wt_session* s, wired_span data);
void srvrun_route_rx_datagram(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 connect_id, wired_span data);
void srvrun_deliver_rx_datagram(
    const srvrun_cfg* cfg, srvrun_conn* c, const wired_srvloop_rx_datagram* dg);
void srvrun_drain_rx_datagrams(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_offer_and_deliver_wt_uni_slot(
    const srvrun_cfg*                 cfg,
    srvrun_conn*                      c,
    wired_srvloop_wt_uni_stream_slot* slot);
void srvrun_grant_wt_uni(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_offer_wt_uni_streams(const srvrun_cfg* cfg, srvrun_conn* c);
u64  srvrun_wt_slot_credit_ceiling(u64 delivered_len);
int  srvrun_wt_credit_stream_due(u64 ceiling, u64 credit_advertised);
int  srvrun_seal_max_stream_data(
    srvrun_conn* c, u64 stream_id, u64 value, wired_obuf* out);
void srvrun_send_max_stream_data(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id, u64 value);

#endif
