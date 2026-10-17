#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_metrics_fill(
    const srvrun_conn* c, wired_qlogevent_metrics_in* m);
static int srvrun_metrics_due(srvrun_conn* c, u64 now_ms);
static int srvrun_metrics_emit_due(const srvrun_step_ctx* ctx, srvrun_conn* c);
static int srvrun_deferred_ack_due(srvrun_conn* c);

void srvrun_reap_wtsends(srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    srvrun_reap_one_wtsend(c, &c->wtsend[i]);
  }
}

/* Sum of receive-window overflow drops across this connection's WT stream
 * reassembly slots (bidi + uni), for the metrics snapshot below and the
 * flow-control check (srvrun_flow_violated). Every slot counts, claimed or
 * not: release keeps a slot's count until its next claim resets the
 * window, so an overrun on a slot released in the same step still closes
 * the connection. */
u64 srvrun_wtwin_dropped(const srvrun_conn* c) {
  u64 total = 0;
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++) {
    total += c->l.wt_streams[i].win.dropped_bytes;
  }
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++) {
    total += c->l.wt_uni_streams[i].win.dropped_bytes;
  }
  return total;
}

/* Snapshot for the qlog recovery:metrics_updated record: RFC 9002 recovery
 * state (stats) plus this connection's WT diagnostic counters. */
static void srvrun_metrics_fill(
    const srvrun_conn* c, wired_qlogevent_metrics_in* m) {
  stats_rtt rtt;
  stats_cc  cc;
  stats_rtt_get(&c->rtt, &rtt);
  stats_cc_get(&c->cc, &cc);
  m->smoothed_rtt    = rtt.smoothed_rtt;
  m->cwnd            = cc.cwnd;
  m->bytes_in_flight = srvrun_inflight_bytes_all(c);
  m->wtsend_ok       = c->stat_wtsend_ok;
  m->wtsend_busy     = c->stat_wtsend_busy;
  m->wtsend_flow     = c->stat_wtsend_flow;
  m->wtwin_drop      = srvrun_wtwin_dropped(c);
  m->streams_blocked = c->stat_streams_blocked;
}

/* 1 once per SRVRUN_METRICS_INTERVAL_MS per connection, arming the next
 * window as a side effect. */
static int srvrun_metrics_due(srvrun_conn* c, u64 now_ms) {
  if (now_ms - c->metrics_emit_ms < SRVRUN_METRICS_INTERVAL_MS) {
    return 0;
  }
  c->metrics_emit_ms = now_ms;
  return 1;
}

/* 1 iff a metrics record should be written this step: a qlog path is
 * configured and this connection's interval has elapsed (arming the next
 * window as a side effect). */
static int srvrun_metrics_emit_due(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  return ctx->cfg->qlog_path && srvrun_metrics_due(c, ctx->now_ms);
}

/* qlog recovery:metrics_updated for one connection, ~1/s (time is srvrun's
 * own monotonic now_ms, the same clock the PTO deadlines run on). No-op
 * without a qlog path. */
void srvrun_qlog_metrics(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  char                       rec[256];
  usz                        n;
  wired_qlogevent_metrics_in m;
  if (!srvrun_metrics_emit_due(ctx, c)) {
    return;
  }
  srvrun_metrics_fill(c, &m);
  n = wired_qlogevent_metrics(rec, sizeof rec, ctx->now_ms, c->qlog_slot, &m);
  if (n) {
    wired_qlog_append(ctx->cfg->qlog_path, wired_span_of((const u8*)rec, n));
  }
}

/* 1 iff this step deferred a bare ACK that is due right now; closes the
 * defer window either way (it spans exactly one step). Down connections
 * flush nothing. */
static int srvrun_deferred_ack_due(srvrun_conn* c) {
  if (!c->up || !c->l.ack_defer) {
    return 0;
  }
  c->l.ack_defer = 0;
  return ackpolicy_should_ack(
      &c->l.app_ack_policy, c->l.now_ms, WIRED_SRVLOOP_MAX_ACK_DELAY_MS);
}

/* RFC 9000 13.2.1/13.2.2: a step whose deferred ACK found no slice to ride
 * flushes it as the traditional bare-ACK datagram, so deferral never delays
 * an ACK past the pre-existing upper bound (the delay window still gates
 * this packet, exactly like respond.c's emit_ack_only did). */
void srvrun_flush_deferred_ack(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  u8  pl[SRVRUN_ACK_ROOM];
  usz al;
  if (!srvrun_deferred_ack_due(c)) {
    return;
  }
  al = wired_srvloop_ack_peek(&c->l, pl, sizeof pl);
  if (al) {
    srvrun_seal_send_slice(ctx, c, wired_span_of(pl, al), c->l.tx_pn++, al);
  }
  srvrun_stage_flush(ctx->cfg); /* the bare ACK stages like a slice; nothing
                                 * later this step would flush it */
}
