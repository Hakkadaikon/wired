#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_REC_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_REC_H

/* Internal to srvrun: RFC 9002 loss recovery over the sent-packet record
 * (srvrun_recover.c) and the RTT / ACK tick pieces around it. */

#include "app/http3/server/srvrun/srvrun_impl_protos4.h"
#include "app/http3/server/srvrun/srvrun_impl_tables.h"

/** RFC 9002 6.2.4: ack-eliciting packets one PTO may send (up to two). */
#define SRVRUN_PTO_PROBES 2

u64  srvrun_loss_delay_us(const srvrun_conn* c);
u64  srvrun_peer_max_ack_delay_us(const srvrun_conn* c);
void srvrun_rtt_update(srvrun_conn* c, u64 sample_ms, u64 ack_delay_us);
void srvrun_rec_on_acks(srvrun_conn* c, u64 now_ms);
void srvrun_rec_detect(srvrun_conn* c, u64 now_ms);
usz  srvrun_bytes_in_flight(const srvrun_conn* c);
usz  srvrun_boot_inflight(const srvrun_conn* c);
int  srvrun_rec_eliciting(const srvrun_conn* c);
int  srvrun_loss_timer_due(const srvrun_conn* c, u64 now_ms);
void srvrun_loss_timer_slot(const srvrun_step_ctx* ctx, int slot);
void srvrun_ack_tick_slot(const srvrun_step_ctx* ctx, int slot);
void srvrun_loss_pass(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 now_ms, u64 largest_before);

/* RFC 9002 6.2 for the boot flight's Initial and Handshake spaces
 * (srvrun_boot.c, srvrun_resend.c, srvrun_boot_pto.c). */
int srvrun_boot_ini_done(const srvrun_conn* c);
usz srvrun_boot_resend_hs(const srvrun_cfg* cfg, srvrun_conn* c, usz max);
usz srvrun_boot_send_hs_upto(
    const srvrun_cfg* cfg, srvrun_conn* c, int confirmed, usz max);
int srvrun_boot_hs_armed(const srvrun_conn* c);
int srvrun_boot_mark(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int sp, int sent);
int  srvrun_resend_ini(const srvrun_step_ctx* ctx, srvrun_conn* c);
int  srvrun_boot_hs_probe(const srvrun_step_ctx* ctx, srvrun_conn* c);
void srvrun_boot_on_client_initial(
    const srvrun_step_ctx* ctx, srvrun_conn* c, wired_mspan dg);

#endif
