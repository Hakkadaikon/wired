#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_PART5_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_PART5_H

#include "app/http3/server/srvrun/srvrun_impl_protos3b.h"

/* A response's field lines: the application's (or one extra) plus the
 * SDK's own Content-Length / Date / Allow, with the value bytes those
 * need. WIRED_HTTP_MAX_FIELDS + 3 holds every app field plus all three. */
typedef struct {
  qpack_field f[WIRED_HTTP_MAX_FIELDS + 3];
  usz         n;
  u8          date[CLOCK_IMF_FIXDATE_LEN];
  u8          len[21]; /* u64 in decimal plus snprintf's NUL */
  u8          allow[H3_METHOD_ALLOW_MAX];
} srvrun_hdrs;

h3resp_fields srvrun_hdrs_app(
    srvrun_hdrs* h, const wired_http_exchange* x, u64 total_len);
int srvrun_status_build(
    const wired_h3reqdrive_req* req,
    u16                         status,
    const qpack_field*          extra,
    wired_obuf*                 out);
int         srvrun_http_fields_unique(const wired_http_exchange* x);
int         srvrun_hdr_name_is(const qpack_field* f, wired_span name);
int         srvrun_hdr_name_is_cstr(wired_span name, const char* want);
int         srvrun_req_is_head(const wired_h3reqdrive_req* r);
const char* srvrun_status_text(u16 status);
wired_span  srvrun_status_body(const wired_h3reqdrive_req* r, u16 status);

void srvrun_pace_refill(const srvrun_step_ctx* ctx, srvrun_conn* c);
void srvrun_pace_charge(srvrun_conn* c, usz bytes);
int  srvrun_pace_ok(const srvrun_step_ctx* ctx, const srvrun_conn* c);
int  srvrun_pace_within_poll_tick(const srvrun_conn* c);
void srvrun_pace_next(const srvrun_step_ctx* ctx, srvrun_conn* c);
u64  srvrun_css_acked(const srvrun_conn* c, u64 bytes);
void srvrun_hystart_range(
    srvrun_conn* c, const wired_sendsess* sess, u64 lo, u64 hi, u64 now);
u64 srvrun_range_hits(const wired_sendsess* sess, u64 lo, u64 hi);
usz srvrun_reap_losses(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    wired_sendsess*    sess,
    u64                stream_id,
    u64                now_ms,
    srvrun_loss_span*  span);
void srvrun_ack_range_wt(srvrun_conn* c, u64 lo, u64 hi, u64 now_ms);
void srvrun_ack_range_resps(srvrun_conn* c, u64 lo, u64 hi, u64 now_ms);
usz  srvrun_reap_losses_wt(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 now_ms, srvrun_loss_span* span);
usz srvrun_reap_losses_all(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 now_ms, srvrun_loss_span* span);
void srvrun_pmtu_reap_ack(srvrun_conn* c, u64 lo, u64 hi);
void srvrun_feed_ack_range(srvrun_conn* c, u64 lo, u64 hi, u64 now_ms);
void srvrun_feed_ecn(srvrun_conn* c, u64 largest_before, u64 now_ms);
int  srvrun_loss_unbroken(
    const srvrun_conn* c, const srvrun_loss_span* s, u64 largest_before);
int  srvrun_loss_long(const srvrun_conn* c, const srvrun_loss_span* s);
void srvrun_feed_acks(
    const srvrun_step_ctx* ctx, const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_pump_datagram(const srvrun_step_ctx* ctx, srvrun_conn* c);
int  srvrun_held_still(const srvrun_conn* c, u8 i);
void srvrun_start_held_resps(const srvrun_step_ctx* ctx, int slot);
void srvrun_start_done_resps(const srvrun_step_ctx* ctx, int slot);
void srvrun_abort_incomplete_reqs(const srvrun_step_ctx* ctx, int slot);
void srvrun_abort_frame_unexpected_reqs(const srvrun_step_ctx* ctx, int slot);
void srvrun_resp_release_bigbuf(wired_srvrun_env* env, srvrun_resp* r);
int  srvrun_resp_streaming_live(const srvrun_resp* r);
usz  srvrun_resp_refill_take(const srvrun_resp* r, usz room);
void srvrun_resp_refill_write(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    int                    slot,
    srvrun_resp*           r,
    usz                    take);
void srvrun_resp_refill(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r);
u64  srvrun_stream_limit_base(const srvrun_step_ctx* ctx);
void srvrun_resp_release_stream(srvrun_conn* c, u64 stream_id);
usz  srvrun_resp_reap(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r);
usz srvrun_reap_one(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r);
void srvrun_reap_resps(const srvrun_step_ctx* ctx, srvrun_conn* c, int slot);
usz  srvrun_resp_stop(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_resp* r, u64 code);
void srvrun_wtsend_stop_notify(
    const srvrun_cfg*          cfg,
    srvrun_conn*               c,
    const srvrun_wtsend*       w,
    const wired_srvloop_reset* e);
usz srvrun_answer_peer_stop(
    const srvrun_step_ctx* ctx, srvrun_conn* c, const wired_srvloop_reset* e);
void srvrun_answer_peer_stops(const srvrun_step_ctx* ctx, srvrun_conn* c);
void srvrun_drop_held_resets(const srvrun_step_ctx* ctx, srvrun_conn* c);
void srvrun_free_reset_reqs(const srvrun_step_ctx* ctx, srvrun_conn* c);
int  srvrun_wtsend_finished(srvrun_wtsend* w);
void srvrun_reap_one_wtsend(srvrun_conn* c, srvrun_wtsend* w);
void srvrun_reap_wtsends(srvrun_conn* c);
u64  srvrun_wtwin_dropped(const srvrun_conn* c);
void srvrun_qlog_metrics(const srvrun_step_ctx* ctx, srvrun_conn* c);
void srvrun_flush_deferred_ack(const srvrun_step_ctx* ctx, srvrun_conn* c);
void srvrun_sess_on_step(const srvrun_step_ctx* ctx, int slot);
int  srvrun_has_outbound(const srvrun_conn* c);
int  srvrun_has_boot_outbound(const srvrun_conn* c);
u64  srvrun_pto_deadline_ms(const srvrun_conn* c, int pto_count);
void srvrun_ku_discard_stale(srvrun_conn* c, u64 now_ms);
int  srvrun_pto_armed(const srvrun_conn* c);
int  srvrun_pto_fire_due(const srvrun_conn* c, u64 now_ms);
void srvrun_pto_slot(const srvrun_step_ctx* ctx, int slot);
void srvrun_rst_retry_slot(const srvrun_step_ctx* ctx, int slot);
void srvrun_wt_app_pending_slot(const srvrun_step_ctx* ctx, int slot);
void srvrun_dg_slot(const srvrun_step_ctx* ctx, int slot);
void srvrun_step_and_reap(const srvrun_step_ctx* ctx, int slot, wired_mspan dg);
void srvrun_boot_partial_ack(const srvrun_step_ctx* ctx, int slot);
void srvrun_boot_flip_from_dcid(
    const srvrun_step_ctx* ctx, srvrun_conn* c, wired_mspan dg);
void srvrun_cold_start(const srvrun_step_ctx* ctx, int slot, wired_mspan dg);
int  srvrun_resend_boot_flight(const srvrun_step_ctx* ctx, srvrun_conn* c);
int  srvrun_boot_pto_waiting(const srvrun_conn* c);
void srvrun_boot_pto_slot(const srvrun_step_ctx* ctx, int slot);
void srvrun_boot_on_initial_discard(srvrun_conn* c, int hs_was_seen);
int  srvrun_closing_tick(const srvrun_step_ctx* ctx, int slot);
void srvrun_fire_ptos(const srvrun_cfg* cfg, srvrun_state* st);
int  srvrun_short_header(wired_mspan dg);
int  srvrun_boot_early_onertt(srvrun_conn* c, wired_mspan dg);
int  srvrun_serve_boot(const srvrun_step_ctx* ctx, int slot, wired_mspan dg);
void srvrun_boot_release_pending(const srvrun_step_ctx* ctx, srvrun_conn* c);
int  srvrun_gen_path_challenge(u8 data[PATH_DATA]);
pathsel_key srvrun_send_key(const srvrun_cfg* cfg, const srvrun_conn* c);
pathsel_key srvrun_arrival_key(const srvrun_step_ctx* ctx);
pathsel_key srvrun_target_key(const srvrun_cfg* cfg, const srvrun_conn* c);
int         srvrun_path_is_valid(const srvrun_conn* c, const pathsel_key* k);
int  srvrun_path_is_gated_target(const srvrun_conn* c, const pathsel_key* k);
void srvrun_path_seed(const srvrun_cfg* cfg, srvrun_conn* c);
int  srvrun_path_tracked(
    const srvrun_cfg* cfg, srvrun_conn* c, const pathsel_key* k);

#endif
