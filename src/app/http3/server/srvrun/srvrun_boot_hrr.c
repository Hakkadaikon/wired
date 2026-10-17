#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_boot_hrr_sent(
    const srvrun_step_ctx* ctx, srvrun_conn* c, usz ini_len);
static void srvrun_boot_wire(
    const srvrun_step_ctx* ctx, srvrun_conn* c, const wired_srvboot_id* sid);
static void srvrun_boot_stash(srvrun_conn* c, const wired_srvboot_out* out);
static int  srvrun_boot_up(
    const srvrun_step_ctx*   ctx,
    int                      slot,
    srvrun_conn*             c,
    wired_mspan              dg,
    const wired_srvboot_id*  sid,
    const wired_srvboot_out* out);

/* RFC 8446 4.1.4: a HelloRetryRequest went out instead of the accept
 * flight. Keep the slot claimed and the accumulator intact (ClientHello2
 * continues the same crypto stream), stash the HRR Initial where the boot
 * PTO resend machinery already looks (boot_ini, with no Handshake
 * datagrams), and report the boot as still pending. */
static int srvrun_boot_hrr_sent(
    const srvrun_step_ctx* ctx, srvrun_conn* c, usz ini_len) {
  c->boot_ini_len     = ini_len;
  c->boot_dgram_count = 0;
  c->boot_dgram_sent  = 0;
  srvrun_boot_send_initial(ctx->cfg, c, "HelloRetryRequest sent\n");
  c->boot_pto_sent_ms = ctx->now_ms;
  c->boot_pto_count   = 0;
  return SRVRUN_BOOT_PENDING;
}

int srvrun_boot_finish(
    const srvrun_step_ctx* ctx, int slot, srvrun_conn* c, wired_mspan dg) {
  int                r;
  wired_obuf         iob  = obuf_of(c->boot_ini, sizeof c->boot_ini);
  wired_obuf         hob  = obuf_of(c->boot_hs, sizeof c->boot_hs);
  wired_srvboot_conn conn = {&c->s, &c->l};
  wired_srvboot_id   sid  = srvrun_slot_id(ctx->cfg->id, c);
  wired_srvboot_out  out  = {&iob, &hob, {0}, 0, 0};
  r = wired_srvboot_accept_acc(&conn, &sid, &c->boot, &out);
  if (!r) return srvrun_refuse(ctx, c);
  if (r == WIRED_SRVBOOT_HRR) return srvrun_boot_hrr_sent(ctx, c, iob.len);
  return srvrun_boot_up(ctx, slot, c, dg, &sid, &out);
}

/* Wire the app's handlers into c's loop and seed its per-connection limits
 * from sid and the peer's ClientHello transport parameters. */
static void srvrun_boot_wire(
    const srvrun_step_ctx* ctx, srvrun_conn* c, const wired_srvboot_id* sid) {
  wired_server_set_keylog_path(&c->s, ctx->cfg->keylog_path);
  wired_srvloop_set_handler(&c->l, ctx->cfg->handler, ctx->cfg->ctx);
  c->l.on_body       = ctx->cfg->on_body;
  c->l.on_body_abort = ctx->cfg->env->on_body_abort;
  c->l.resp_external = 1; /* srvrun streams the response (multi-packet) */
  /* RFC 9221 3: this connection's own advertised max_datagram_frame_size,
   * threaded to dispatch.c's DATAGRAM-gathering size check (see
   * wired_srvloop.we_advertised_max_datagram's doc). Same sid/base value
   * stp_build_server_lim already sends in the transport parameters --
   * sid is this slot's own copy of cfg->id, built above. */
  c->l.we_advertised_max_datagram = sid->max_datagram_frame_size;
  /* RFC 9000 18.2/19.9: seed this connection's send credit from the peer's
   * ClientHello TP now that sdrv_recv_client_hello has run (inside
   * wired_srvboot_accept_acc above); MAX_DATA frames only ever raise it
   * from here (srvrun_ku_discard_stale's neighbors gather_max_data /
   * srvrun_sess_on_step apply those raises each step). */
  c->conn_credit = c->s.sdrv.peer_initial_max_data;
}

/* Record the accept flight's Initial and Handshake datagram lengths so the
 * boot send/PTO paths can (re)send it. */
static void srvrun_boot_stash(srvrun_conn* c, const wired_srvboot_out* out) {
  c->boot_ini_len = out->initial->len;
  for (usz i = 0; i < out->dgram_count; i++)
    c->boot_dgram_len[i] = out->dgram_len[i];
  c->boot_dgram_count = out->dgram_count;
  c->boot_dgram_sent  = 0;
}

/* The accept flight is built: finish bringing the connection up -- wire the
 * handler, seed credits, stash the flight for retransmission, and send it
 * (the tail half of srvrun_boot_finish, split so the HRR branch above keeps
 * the head at the CCN gate). */
static int srvrun_boot_up(
    const srvrun_step_ctx*   ctx,
    int                      slot,
    srvrun_conn*             c,
    wired_mspan              dg,
    const wired_srvboot_id*  sid,
    const wired_srvboot_out* out) {
  srvrun_qlog_recv(ctx->cfg, c, out->client_pn, dg.n);
  srvrun_boot_wire(ctx, c, sid);
  srvrun_boot_stash(c, out);
  srvrun_boot_send_initial(ctx->cfg, c, "server Initial sent\n");
  srvrun_boot_send_hs_gated(ctx->cfg, c, wired_server_is_confirmed(&c->s));
  srvrun_boot_flush_zerortt(ctx, c, slot);
  wired_srvboot_acc_reset(&c->boot); /* the reassembly buffer is spent */
  /* RFC 9002 6.2: the accept flight just went out -- start this slot's boot
   * PTO clock fresh (any real send, not just the timer's own probe,
   * pushes the next deadline out so the two re-send paths never double
   * fire). */
  c->boot_pto_sent_ms = ctx->now_ms;
  c->boot_pto_count   = 0;
  return 1;
}
