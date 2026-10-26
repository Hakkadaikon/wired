#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_H

#include "app/http3/server/srvrun/srvrun_impl_protos4.h"
#include "app/http3/server/srvrun/srvrun_impl_token.h"
#include "app/http3/server/srvrun/srvrun_impl_wtflow.h"

const peercid_entry* srvrun_path_cid(
    const srvrun_cfg* cfg, srvrun_conn* c, const pathsel_key* k, int kept);
void srvrun_path_move(
    const srvrun_cfg* cfg, srvrun_conn* c, const pathsel_key* k);
/** srvrun_path_send's result for a datagram sent below 1200 bytes. */
#define SRVRUN_PATH_SMALL 2
int srvrun_path_send(
    const srvrun_cfg*    cfg,
    srvrun_conn*         c,
    const pathsel_key*   k,
    const peercid_entry* e,
    u8                   type,
    const u8*            data,
    usz                  n);
void srvrun_path_note_rx(const srvrun_step_ctx* ctx, srvrun_conn* c, usz n);
int  srvrun_rst_room(srvrun_conn* c);
void srvrun_path_note_err(srvrun_conn* c, int err);
void srvrun_path_take_retires(const srvrun_step_ctx* ctx, srvrun_conn* c);
int  srvrun_peer_reset_hit(const srvrun_conn* c, wired_mspan dg);
void srvrun_peer_reset_drain(const srvrun_step_ctx* ctx, int slot);
int  srvrun_peer_reset_any(const srvrun_step_ctx* ctx, wired_mspan dg);
void srvrun_path_cc_restart(
    const srvrun_cfg* cfg, srvrun_conn* c, const pathsel_key* k);
int  srvrun_path_port_only(const pathsel_key* a, const pathsel_key* b);
void srvrun_pmtu_start(srvrun_conn* c);
void srvrun_pmtu_path_reset(
    srvrun_conn* c, const pathsel_key* from, const pathsel_key* to);
u64  srvrun_path_budget(srvrun_conn* c, const pathsel_key* k);
int  srvrun_path_spend(srvrun_conn* c, const pathsel_key* k, usz n);
void srvrun_path_challenge(
    const srvrun_cfg* cfg, srvrun_conn* c, pathsel_slot* s, u64 now);
void srvrun_path_arm(
    const srvrun_cfg* cfg, srvrun_conn* c, pathsel_slot* s, u64 now);
void srvrun_path_chal_new(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    const pathsel_key*     to,
    const pathsel_key*     from);
void srvrun_path_chal_old(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    const pathsel_key*     from,
    const pathsel_key*     to);
int srvrun_path_gates(
    const srvrun_cfg* cfg, const srvrun_conn* c, const pathsel_key* k);
void srvrun_path_switch(const srvrun_step_ctx* ctx, srvrun_conn* c, int kept);
int  srvrun_path_reverts(const srvrun_step_ctx* ctx, const srvrun_conn* c);
int  srvrun_rebind_due(const srvrun_step_ctx* ctx, const srvrun_conn* c);
void srvrun_path_probe(const srvrun_step_ctx* ctx, srvrun_conn* c, int kept);
void srvrun_apply_path_response(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_path_expire(const srvrun_cfg* cfg, srvrun_conn* c, u64 now);
void srvrun_path_resend(const srvrun_cfg* cfg, srvrun_conn* c, u64 now);
void srvrun_path_retire(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_path_tick(const srvrun_step_ctx* ctx, srvrun_conn* c);
void srvrun_path_take_cids(const srvrun_cfg* cfg, srvrun_conn* c);
int  srvrun_dcid_room(const srvrun_conn* c, wired_mspan dg);
int  srvrun_dcid_kept(const srvrun_conn* c, wired_mspan dg);
void srvrun_path_step(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    wired_mspan            dg,
    const srvrun_rxmark*   mark);
void srvrun_reconfirm_on_hs_probe(
    const srvrun_step_ctx* ctx, srvrun_conn* c, wired_mspan dg);
int  srvrun_hs_probe_pending(const srvrun_conn* c, int booting, wired_mspan dg);
int  srvrun_send_boot_probe(const srvrun_step_ctx* ctx, srvrun_conn* c);
int  srvrun_boot_probe_or_replay(const srvrun_step_ctx* ctx, srvrun_conn* c);
void srvrun_flush_held_on_confirm(
    const srvrun_step_ctx* ctx, int slot, int booting);
void srvrun_serve_slot(const srvrun_step_ctx* ctx, int slot, wired_mspan dg);
wired_span srvrun_dcid(wired_mspan dg, u8 short_hdr_len);
int        srvrun_find_slot(const srvrun_step_ctx* ctx, wired_span dcid);
int        srvrun_claim_refused(wired_span dcid, int is_initial);
int        srvrun_claim_slot(
    const srvrun_step_ctx* ctx, wired_span dcid, int is_initial);
int  srvrun_issue_cid(const srvrun_cfg* cfg, u8* cid, u8 cid_len);
int  srvrun_cc_algo(const srvrun_cfg* cfg);
void srvrun_issue_spare_cid(const srvrun_cfg* cfg, srvrun_conn* c);
int  srvrun_open_slot(
    const srvrun_step_ctx* ctx, wired_span dcid, int is_initial);
usz srvrun_retry_pkt_build(
    const lhdr* h,
    u32         version,
    const u8    scid[8],
    wired_span  token,
    u8*         pkt,
    usz         cap);
void srvrun_retry_scid_distinct(u8 scid[8], wired_span dcid);
/* A tagged Retry token: TOKEN_TAG_RETRY || the retrytoken wire token. */
#define SRVRUN_RETRY_TOKEN_MAX (1 + RETRYTOKEN_WIRE_MAX)
void srvrun_retry_prep(
    const srvrun_step_ctx* ctx,
    const lhdr*            h,
    u8                     scid[8],
    u8                     token[SRVRUN_RETRY_TOKEN_MAX],
    usz*                   tn);
void srvrun_retry_finish(
    const srvrun_step_ctx* ctx, const lhdr* h, u32 version, u8* pkt, usz n);
int srvrun_retry_gate(
    const srvrun_step_ctx* ctx,
    wired_mspan            dg,
    wired_span*            odcid,
    int*                   validated);
void srvrun_note_retry_odcid(srvrun_conn* c, wired_span odcid);
int  srvrun_vneg(const srvrun_step_ctx* ctx, wired_mspan dg);
int  srvrun_find_boot_scid(const srvrun_step_ctx* ctx, wired_span dcid);
int  srvrun_route(const srvrun_step_ctx* ctx, wired_span dcid, wired_mspan dg);
int  srvrun_evict_for_initial(
    const srvrun_step_ctx* ctx, wired_span dcid, int is_initial);
void srvrun_send_stateless_reset(
    const srvrun_step_ctx* ctx, wired_span dcid, wired_mspan dg);
int srvrun_route_or_evict(
    const srvrun_step_ctx* ctx, wired_span dcid, wired_mspan dg);
void srvrun_send_new_conn_refusal(
    const srvrun_step_ctx* ctx, wired_span dcid, wired_mspan dg);
int srvrun_retry_applies(
    const srvrun_step_ctx* ctx, wired_span dcid, wired_mspan dg);
int srvrun_retry_consumed(
    const srvrun_step_ctx* ctx,
    wired_span             dcid,
    wired_mspan            dg,
    wired_span*            odcid,
    int*                   validated);
int  srvrun_ghost_match(const srvrun_step_ctx* ctx, wired_span dcid);
void srvrun_note_ghost(const srvrun_step_ctx* ctx, srvrun_conn* c);
void srvrun_serve(const srvrun_step_ctx* ctx, wired_mspan dg);
i64  srvrun_listen(u16 port, const wired_srvrun_opt* opt);
void srvrun_serve_batch(
    const srvrun_cfg* cfg, srvrun_state* st, const mmsg_buf* bufs, i64 n);
int  srvrun_slot_waiting(const srvrun_conn* c);
int  srvrun_any_waiting(const srvrun_state* st);
int  srvrun_pto_due(const srvrun_cfg* cfg, wired_srvrun_env* env);
void srvrun_polling_ptos(const srvrun_cfg* cfg, srvrun_state* st);
int  srvrun_may_block_unbounded(const srvrun_cfg* cfg, srvrun_state* st);
int  srvrun_wait_input(const srvrun_cfg* cfg, srvrun_state* st);
i64  srvrun_recv(const srvrun_cfg* cfg, mmsg_buf* bufs, usz nbufs);
void srvrun_step(
    const srvrun_cfg* cfg, srvrun_state* st, mmsg_buf* bufs, usz nbufs);
void srvrun_loop(const srvrun_cfg* cfg);
void srvrun_install_sighup(const srvrun_cfg* cfg);
void srvrun_install_signals(const srvrun_cfg* cfg, const wired_srvrun_opt* opt);
srvrun_cfg srvrun_build_cfg(
    wired_srvrun_env*       env,
    u16                     port,
    wired_srvboot_id*       id,
    wired_srvrun_handler    h,
    wired_srvrun_obs        obs,
    const wired_srvrun_opt* opt);
void srvrun_pref_listen(
    srvrun_cfg* cfg, wired_srvboot_id* id, const wired_srvrun_opt* opt);
void srvrun_pin_reset_seed(wired_srvrun_env* env, wired_srvboot_id* id);

extern wired_srvrun_env   g_srvrun_env;
extern srvrun_bcast_entry g_srvrun_bcast[SRVRUN_BCAST_MAX];
extern int g_srvrun_bcast_n; /* registered entry count (atomic) */
;

#include "app/http3/server/srvrun/srvrun_impl_rec.h"

#endif
