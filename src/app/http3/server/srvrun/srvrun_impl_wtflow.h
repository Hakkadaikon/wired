#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_WTFLOW_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_WTFLOW_H

#include "app/http3/server/srvrun/srvrun_impl_protos4.h"

/* WebTransport flow, teardown and reset (srvrun_open.c, srvrun_wt_shut.c,
 * srvrun_wt.c). */
void srvrun_wt_notify_data_blocked(
    srvrun_conn* c, int sidx, wired_wt_session* s, usz len);
void srvrun_wt_close_all_live(const srvrun_cfg* cfg, srvrun_state* st);
void srvrun_wt_close_wait_note(srvrun_conn* c);
int  srvrun_wt_close_waiting(const srvrun_state* st);
usz  srvrun_wt_reset_frames(
    const srvrun_conn* c, const srvrun_wt_reset_in* in, u8* p, usz cap);

/* draft-ietf-webtrans-http3-16 6: data after the peer's WT_CLOSE_SESSION
 * (srvrun_wt_watch.c, srvrun_wt_capsule.c). */
void srvrun_reset_stream_final(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 id, u64 final, u64 code);
u64 srvrun_wt_rx_fail_code(
    srvrun_conn*                     c,
    int                              sidx,
    const wired_srvloop_stream_slot* slot,
    const srvrun_wt_caprx*           x);
void srvrun_wt_watch_drain(const srvrun_cfg* cfg, srvrun_conn* c);

#endif
