#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_REC_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_REC_H

/* Internal to srvrun: RFC 9002 loss recovery over the sent-packet record
 * (srvrun_recover.c) and the RTT / ACK tick pieces around it. */

#include "app/http3/server/srvrun/srvrun_impl_protos4.h"

u64  srvrun_loss_delay_us(const srvrun_conn* c);
u64  srvrun_peer_max_ack_delay_us(const srvrun_conn* c);
void srvrun_rtt_update(srvrun_conn* c, u64 sample_ms, u64 ack_delay_us);
void srvrun_rec_on_acks(srvrun_conn* c, u64 now_ms);
void srvrun_rec_detect(srvrun_conn* c, u64 now_ms);
usz  srvrun_bytes_in_flight(const srvrun_conn* c);
int  srvrun_loss_timer_due(const srvrun_conn* c, u64 now_ms);
void srvrun_loss_timer_slot(const srvrun_step_ctx* ctx, int slot);
void srvrun_ack_tick_slot(const srvrun_step_ctx* ctx, int slot);
void srvrun_loss_pass(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 now_ms, u64 largest_before);

#endif
