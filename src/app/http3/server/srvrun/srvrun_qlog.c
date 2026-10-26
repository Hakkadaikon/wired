#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_qlog_lost_packet(
    const srvrun_cfg* cfg, const srvrun_conn* c, u64 now_ms, u64 pn);
static void srvrun_qlog_lost_stream_frame(
    const srvrun_cfg*                cfg,
    const srvrun_conn*               c,
    u64                              now_ms,
    u64                              stream_id,
    const wired_sendsess_lost_slice* l);
static void srvrun_qlog_lost_one(
    const srvrun_cfg*                cfg,
    const srvrun_conn*               c,
    u64                              now_ms,
    u64                              stream_id,
    const wired_sendsess_lost_slice* l);
static int srvrun_confirm_edge(const srvrun_conn* c, int was_booting);
static int srvrun_boot_rtt_unseeded(const srvrun_conn* c);

void srvrun_pump_sess(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  /* RFC 9001 4.1.2 / RFC 9000 12.3: 1-RTT packet-protection keys (the SDK's
   * own send_onertt_keys fallback, srvloop/send.c) do not exist until the
   * server's own Finished-inclusive transcript confirms
   * (keysched_advance_master, srvfin/complete.c) -- a response started
   * from a 0-RTT-carried request (srvrun_boot_flush_zerortt, or the live
   * 0-RTT path before the client's Finished lands) can be CLAIMED and armed
   * before that point, but sending its slices this early always fails
   * closed at the key layer. Deferring the whole pump until confirmed costs
   * nothing: the next post-confirm step (the client's own Finished, which
   * confirms) drains every slot's already-armed sendq exactly as if it had
   * started then. */
  if (!wired_server_is_confirmed(&c->s)) {
    return;
  }
  srvrun_acct_resync(c); /* pick up ACK/requeue/reap/re-arm effects wholesale
                          * before any gate reads the cached totals */
  srvrun_prio_refresh(c);
  srvrun_pace_refill(ctx, c);
  while (srvrun_pump_opportunity(ctx, c)) {
  }
  srvrun_note_app_limited(ctx, c);
  srvrun_notify_uni_blocked(ctx->cfg, c);
  srvrun_stage_flush(ctx->cfg); /* the pass's staged slices leave as one
                                 * GSO batch (srvrun_send_staged) */
}

/* After a live step: feed the step's ACK ranges to the session, start a
 * response for a freshly decoded request, and send what the window allows.
 * A finished session simply goes idle. */
/* qlog packet_lost (connection-level trend) for one lost pn. No-op without a
 * qlog path -- callers only reach here after their own gate already
 * confirmed one. */
static void srvrun_qlog_lost_packet(
    const srvrun_cfg* cfg, const srvrun_conn* c, u64 now_ms, u64 pn) {
  char rec[128];
  usz  w =
      wired_qlogevent_packet_lost(rec, sizeof rec, now_ms, c->qlog_slot, pn);
  if (w) {
    wired_qlog_append(cfg->qlog_path, wired_span_of((const u8*)rec, w));
  }
}

/* qlog stream_frame_lost (frame-level forensics: moqt-voice-stability
 * addendum 4/5's "did the server see loss, did it resend" question) for one
 * declared-lost slice. */
static void srvrun_qlog_lost_stream_frame(
    const srvrun_cfg*                cfg,
    const srvrun_conn*               c,
    u64                              now_ms,
    u64                              stream_id,
    const wired_sendsess_lost_slice* l) {
  char                            rec[192];
  wired_qlogevent_stream_frame_in in = {
      stream_id, l->offset, l->length, l->fin, l->pn};
  usz w = wired_qlogevent_stream_frame(
      rec, sizeof rec, now_ms, c->qlog_slot, "stream_frame_lost", &in);
  if (w) {
    wired_qlog_append(cfg->qlog_path, wired_span_of((const u8*)rec, w));
  }
}

/* Both qlog records for one declared-lost slice -- packet_lost stays for
 * existing connection-trend tooling, stream_frame_lost is the new
 * frame-level forensic record; both fire, they serve different uses. No-op
 * without a qlog path. */
static void srvrun_qlog_lost_one(
    const srvrun_cfg*                cfg,
    const srvrun_conn*               c,
    u64                              now_ms,
    u64                              stream_id,
    const wired_sendsess_lost_slice* l) {
  if (!cfg->qlog_path) {
    return;
  }
  srvrun_qlog_lost_packet(cfg, c, now_ms, l->pn);
  srvrun_qlog_lost_stream_frame(cfg, c, now_ms, stream_id, l);
}

void srvrun_qlog_lost(
    const srvrun_cfg*                cfg,
    const srvrun_conn*               c,
    u64                              now_ms,
    u64                              stream_id,
    const wired_sendsess_lost_slice* lost,
    usz                              n) {
  for (usz i = 0; i < n; i++) {
    srvrun_qlog_lost_one(cfg, c, now_ms, stream_id, &lost[i]);
  }
}

/* Consume this step's ACK ranges, then declare packet-threshold losses so
 * their slices requeue ahead of new data (RFC 9002 6.1.1), logging each
 * lost packet to the qlog when one is configured. */
/* RFC 9002 5.3 (shape): seed on the first sample, then 7/8 old + 1/8 new.
 * Also feeds the full RFC 9002 5 estimator (rtt, us) that
 * srvrun_pto_deadline_ms needs for rttvar, with the peer's ACK Delay and
 * max_ack_delay (5.3) -- srtt_ms above stays the simpler ms-only EWMA
 * pacing already relies on, unchanged. */
void srvrun_rtt_update(srvrun_conn* c, u64 sample_ms, u64 ack_delay_us) {
  if (!c->rtt.have_sample) {
    c->rtt_from_pn = c->l.tx_pn;
  }
  c->latest_rtt_ms = sample_ms;
  c->srtt_ms       = c->srtt_ms ? (7 * c->srtt_ms + sample_ms) / 8 : sample_ms;
  rtt_sample(
      &c->rtt, sample_ms * 1000, ack_delay_us, srvrun_peer_max_ack_delay_us(c),
      wired_server_is_confirmed(&c->s));
}

/* srvrun_rtt_update for a sample no peer ACK Delay applies to (the
 * handshake-measured boot sample). */
void srvrun_rtt_note(srvrun_conn* c, u64 sample_ms) {
  srvrun_rtt_update(c, sample_ms, 0);
}

/* 1 if confirmation landed on the datagram just processed: c was still
 * awaiting confirm before it (was_booting) and is confirmed now. */
static int srvrun_confirm_edge(const srvrun_conn* c, int was_booting) {
  return was_booting && wired_server_is_confirmed(&c->s);
}

/* 1 while no RTT sample exists yet and a boot send timestamp is there to
 * measure against. */
static int srvrun_boot_rtt_unseeded(const srvrun_conn* c) {
  return !c->srtt_ms && c->boot_pto_sent_ms != 0;
}

/* RFC 9002 6.2.2: before the first 1-RTT ACK the PTO deadline falls back to
 * the kInitialRtt-based ~1s default -- but the handshake itself already
 * measured the path once: the client's confirming flight answers the boot
 * flight last sent at boot_pto_sent_ms. Seed both estimators with that one
 * sample at the confirm transition, so a first post-confirm loss probes on
 * the real path RTT instead of waiting out the ~1s floor (the dominant
 * cost per connection under the interop runner's handshakeloss profile). */
void srvrun_seed_boot_rtt(srvrun_conn* c, int was_booting, u64 now_ms) {
  if (!srvrun_confirm_edge(c, was_booting)) {
    return;
  }
  if (!srvrun_boot_rtt_unseeded(c)) {
    return;
  }
  srvrun_rtt_note(c, now_ms - c->boot_pto_sent_ms);
}
