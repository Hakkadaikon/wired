#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_send_retire(const srvrun_cfg* cfg, srvrun_conn* c, u64 seq);
static void srvrun_path_keys(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    pathsel_key        t[3 + PATHSEL_SLOTS]);
static int srvrun_path_live(const srvrun_conn* c);

/* Seal one RETIRE_CONNECTION_ID frame (RFC 9000 19.16) as its own 1-RTT
 * packet, kept for resending until ACKed (13.3), and send it on the send
 * path. */
static void srvrun_send_retire(const srvrun_cfg* cfg, srvrun_conn* c, u64 seq) {
  u8 pl[16];
  srvrun_send_kept(
      cfg, c, pl, retire_cid_encode(pl, sizeof pl, seq),
      "RETIRE_CONNECTION_ID sent\n");
}

/* The paths whose peer IDs stay: send, last validated, target, slots. */
static void srvrun_path_keys(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    pathsel_key        t[3 + PATHSEL_SLOTS]) {
  t[0] = srvrun_send_key(cfg, c);
  t[1] = c->path.last_valid;
  t[2] = srvrun_target_key(cfg, c);
  for (usz i = 0; i < PATHSEL_SLOTS; i++) {
    t[3 + i] = c->path.slot[i].in_use ? c->path.slot[i].key : t[0];
  }
}

/* RFC 9000 5.1.2: retire the peer IDs no tracked path uses and those the
 * peer asked to retire. Each RETIRE_CONNECTION_ID is resent until ACKed; one
 * is taken off the queue (at most PEERCID_RETIRE, twice the default
 * active_connection_id_limit) only while a resend entry is free, which
 * bounds the retirements awaiting acknowledgment. */
void srvrun_path_retire(const srvrun_cfg* cfg, srvrun_conn* c) {
  pathsel_key t[3 + PATHSEL_SLOTS];
  u64         seq;
  srvrun_path_keys(cfg, c, t);
  peercid_sweep(&c->pcid, t, 3 + PATHSEL_SLOTS);
  while (srvrun_rst_room(c) && peercid_take_retire(&c->pcid, &seq)) {
    srvrun_send_retire(cfg, c, seq);
  }
}

static int srvrun_path_live(const srvrun_conn* c) {
  return c->up && c->path.seeded && !c->closing;
}

/* The path timers on a tick: abandon (8.2.4), resend (9.4), retire. */
void srvrun_path_tick(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (!srvrun_path_live(c)) {
    return;
  }
  srvrun_path_expire(ctx->cfg, c, ctx->now_ms);
  srvrun_path_resend(ctx->cfg, c, ctx->now_ms);
  srvrun_path_retire(ctx->cfg, c);
}

/* Keep the first connection ID error of the step (srvrun_close_on_cid). */
void srvrun_path_note_err(srvrun_conn* c, int err) {
  c->cid_err = c->cid_err ? c->cid_err : (u8)err;
}

/* RFC 9000 5.1/19.15: store this step's NEW_CONNECTION_ID frames (a
 * violation closes at the step's end, srvrun_close_on_cid); the send path
 * then takes a fresh ID if its own was retired. */
void srvrun_path_take_cids(const srvrun_cfg* cfg, srvrun_conn* c) {
  pathsel_key s = srvrun_send_key(cfg, c);
  for (usz i = 0; i < c->l.ncid_rx_n; i++) {
    srvrun_path_note_err(c, peercid_add(&c->pcid, &c->l.ncid_rx[i]));
  }
  c->l.ncid_rx_n = 0;
  srvrun_path_move(cfg, c, &s);
}

/* dg leads with a short header long enough to hold a server ID. */
int srvrun_dcid_room(const srvrun_conn* c, wired_mspan dg) {
  return srvrun_short_header(dg) && dg.n > (usz)c->s.sdrv.iscid_len;
}

/* RFC 9000 9.5: dg carries the same server ID as the client's last packet. */
int srvrun_dcid_kept(const srvrun_conn* c, wired_mspan dg) {
  if (!srvrun_dcid_room(c, dg)) {
    return 0;
  }
  return ct_diffn(dg.p + 1, c->rx_dcid, c->s.sdrv.iscid_len) == 0;
}
