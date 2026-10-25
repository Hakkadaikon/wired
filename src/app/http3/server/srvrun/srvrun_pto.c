#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_pto_wtsends(srvrun_conn* c, u64 now_ms);
static int srvrun_pto_all(srvrun_conn* c, u64 now_ms);

/* The wtsend half of the probe pass, same budget policy. */
static int srvrun_pto_wtsends(srvrun_conn* c, u64 now_ms) {
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    if (!srvrun_sess_pto_ok(
            c, &c->wtsend[i].sess, c->wtsend[i].in_use, now_ms)) {
      return 0;
    }
  }
  return 1;
}

/* 1 while every in-flight send session (resp[] and wtsend) still has probe
 * budget; 0 tears the connection slot down (the peer went silent on the
 * whole connection, not one stream -- see srvrun_pto_resps' doc above). */
static int srvrun_pto_all(srvrun_conn* c, u64 now_ms) {
  return srvrun_pto_resps(c, now_ms) && srvrun_pto_wtsends(c, now_ms);
}

void srvrun_pto_slot(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (!srvrun_sess_waiting(c)) {
    return;
  }
  if (!srvrun_pto_all(c, ctx->now_ms)) {
    srvrun_log_close(
        "conn dropped: probe budget exhausted", wired_span_of(0, 0));
    srvrun_free_slot(ctx->cfg, ctx->st, slot);
    return;
  }
  srvrun_pump_sess(ctx, slot);
}

/* srvrun_rst_retry for a live slot. A kept control packet still unACKed
 * after its whole resend budget gets the same answer as unACKed stream data
 * (srvrun_pto_slot): the peer stopped answering, so the connection is torn
 * down rather than left with the frame silently forgotten. A slot that
 * went down drops its entries with everything else. */
void srvrun_rst_retry_slot(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (c->up && !srvrun_rst_retry(ctx->cfg, c, ctx->now_ms)) {
    srvrun_log_close(
        "conn dropped: control resend budget exhausted", wired_span_of(0, 0));
    srvrun_free_slot(ctx->cfg, ctx->st, slot);
  }
}

/* The counterpart to srvrun_rst_retry_slot for the three WT app-callback
 * latches (srvrun_wt_app_pending's own doc): a poll-timeout tick, not only
 * a packet the peer happens to send, must also flush them, since the app
 * can call wired_server_wt_close_session/wt_drain_session/wt_stream_reset
 * from a tick/on_step hook with no packet of that peer's own in flight. */
void srvrun_wt_app_pending_slot(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (!c->up) {
    return;
  }
  srvrun_flush_wt_drain(c);
  srvrun_drain_wt_close_pending(ctx->cfg, c);
  srvrun_drain_wt_stream_reset(ctx->cfg, c);
}

/* Flush one slot's queued broadcast DATAGRAM (if any) on a poll-loop tick --
 * the counterpart to srvrun_pto_slot for dg_pending, since a receive-only
 * peer (e.g. a WebTransport client that only listens) never runs
 * srvrun_sess_on_step's own srvrun_pump_datagram call on its own. */
void srvrun_dg_slot(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (c->up) {
    srvrun_pump_datagram(ctx, c);
  }
}

/* One live step; a peer CONNECTION_CLOSE observed by the loop frees the slot
 * afterward (RFC 9000 10.2.2: the connection is done, its state discarded). */
void srvrun_step_and_reap(
    const srvrun_step_ctx* ctx, int slot, wired_mspan dg) {
  srvrun_conn* c = &ctx->st->conns[slot];
  srvrun_on_step(ctx, c, dg);
  if (c->l.peer_closed) {
    srvrun_log_close_alert(
        "conn closed by peer (CONNECTION_CLOSE)", c->l.peer_close_code);
    srvrun_note_ghost(ctx, c); /* swallow its closing-period stragglers */
    srvrun_free_slot(ctx->cfg, ctx->st, slot);
    return;
  }
  srvrun_sess_on_step(ctx, slot);
}

/* Drive one received datagram against its resolved slot: a new Initial
 * (re)opens the connection, any other datagram steps the live loop. */
/* Drive one cold-start feeding: a pending boot keeps its claim (and its
 * accumulator) for the next datagram; success or failure settles the slot. */
/* RFC 9000 13.2.1 while the ClientHello is still incomplete: ack the
 * Initial packets that did arrive, so a client whose missing piece keeps
 * getting dropped hears the server is alive instead of dying on its own
 * handshake idle timer. That ack is the slot's first packet, which makes
 * the client switch its DCID to our scid (RFC 9000 7.2) -- rekey the
 * routing entry and admit the new DCID into the accumulator before the
 * switched retransmits arrive. The antiamp gate still bounds the send. */
void srvrun_boot_partial_ack(const srvrun_step_ctx* ctx, int slot) {
  u8           out[1400];
  srvrun_conn* c    = &ctx->st->conns[slot];
  wired_span   scid = wired_span_of(c->scid, ctx->cfg->id->scid_len);
  usz          n = wired_srvboot_partial_ack(&c->boot, scid, out, sizeof out);
  if (n == 0) {
    return;
  }
  if (srvrun_boot_gate_blocks(c, 0, n)) {
    return;
  }
  /* The routing entry stays keyed on the ODCID: pre-switch retransmits
   * still arrive under it, and rekeying here let them claim a COMPETING
   * slot whose flight carried a different initial_source_connection_id
   * (observed live: quic-go closed with TRANSPORT_PARAMETER_ERROR).
   * Post-switch datagrams route via srvrun_find_boot_scid instead. */
  wired_srvboot_acc_allow(&c->boot, scid);
  srvrun_boot_send(
      ctx->cfg, c, wired_span_of(out, n), "partial ClientHello acked\n");
}
