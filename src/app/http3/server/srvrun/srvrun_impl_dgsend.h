#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_DGSEND_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_DGSEND_H

/* Session-addressed DATAGRAM ring: send side (srvrun_dgring_send.c). */
#include "app/http3/server/srvrun/srvrun_impl_protos2.h"

int srvrun_dgring_send_one(
    const srvrun_cfg*          cfg,
    srvrun_state*              st,
    const srvrun_dgring_entry* e,
    u64                        now_ms);
int srvrun_dg_cwnd_blocked(const srvrun_conn* c, usz len);
int srvrun_dg_refill_held(srvrun_conn* c, usz len, u64 now_ms);
/* RFC 9221 5.1: send the most urgent unsent ring entry whose connection's
 * window and pacer allow it at now_ms; 0 when none can be sent. */
int srvrun_dgring_send_best(
    const srvrun_cfg* cfg, srvrun_state* st, u64 now_ms);
void srvrun_dgring_drain(const srvrun_cfg* cfg, srvrun_state* st, u64 now_ms);

#endif
