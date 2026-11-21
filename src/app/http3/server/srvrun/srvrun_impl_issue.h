#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_ISSUE_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_ISSUE_H

/* Internal to srvrun: routing a datagram's DCID to its slot and issuing
 * this server's own connection IDs (srvrun_claim.c / srvrun_retry.c).
 * Split from srvrun_impl.h, which includes this header after the
 * srvrun_cfg / srvrun_step_ctx types it needs; not for direct inclusion. */

wired_span srvrun_dcid(wired_mspan dg, u8 short_hdr_len);
int        srvrun_find_slot(const srvrun_step_ctx* ctx, wired_span dcid);
int        srvrun_claim_refused(wired_span dcid, int is_initial);
int        srvrun_claim_slot(
    const srvrun_step_ctx* ctx, wired_span dcid, int is_initial);
int srvrun_issue_cid(
    const srvrun_cfg* cfg, const conntable* t, u8* cid, u8 cid_len);
/* 1 when this run embeds its worker index into issued CIDs under the
 * reuseport steering key (srvrun_claim.c). */
int  srvrun_udp_steer_routing(const srvrun_cfg* cfg);
void srvrun_issue_spare_cid(
    const srvrun_cfg* cfg, const conntable* t, srvrun_conn* c);
int srvrun_open_slot(
    const srvrun_step_ctx* ctx, wired_span dcid, int is_initial);

#endif
