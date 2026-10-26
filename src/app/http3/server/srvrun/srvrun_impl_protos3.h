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
void srvrun_send_continues(const srvrun_step_ctx* ctx, int slot);
u64  srvrun_continue_shift(const srvrun_conn* c, u64 stream_id);
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

#endif
