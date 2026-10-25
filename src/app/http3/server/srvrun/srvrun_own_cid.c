#include "app/http3/server/srvrun/srvrun_impl.h"

/* One connection ID this server issued: its bytes, its sequence number,
 * and whether it is the routing table's primary entry (else alt2). */
typedef struct {
  u8*  cid;
  u8   len;
  u64* seq;
  int  primary;
} srvrun_own_id;

static int  srvrun_retire_unissued(const srvrun_conn* c, u64 seq);
static int  srvrun_own_of(srvrun_conn* c, u64 seq, srvrun_own_id* o);
static void srvrun_own_route(
    const srvrun_step_ctx* ctx, const srvrun_conn* c, const srvrun_own_id* o);
static void srvrun_own_announce(
    const srvrun_cfg* cfg, srvrun_conn* c, const srvrun_own_id* o);
static void srvrun_own_reissue(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_own_id* o);
static void srvrun_take_retire(
    const srvrun_step_ctx* ctx, srvrun_conn* c, u64 seq);

/* --- RFC 9000 5.1.1/5.1.2/19.16: the peer retiring our connection IDs ---
 *
 * The server keeps two issued IDs live: the handshake's (scid, routed as
 * the table's primary entry) and the spare (l.spare_cid, alt2). When the
 * peer retires one, it is replaced by a fresh ID with the next sequence
 * number -- routed from now on in its place, the retired one no longer --
 * and announced in a NEW_CONNECTION_ID kept until ACKed (13.3), so the
 * peer always has an ID to migrate to. */

/* RFC 9000 19.16: seq was never issued (MUST be a PROTOCOL_VIOLATION). */
static int srvrun_retire_unissued(const srvrun_conn* c, u64 seq) {
  return seq >= u64_max(c->cid_next_seq, 1);
}

/* The live issued ID numbered seq into o; 0 if it was already retired. */
static int srvrun_own_of(srvrun_conn* c, u64 seq, srvrun_own_id* o) {
  if (seq == c->scid_seq) {
    *o = (srvrun_own_id){c->scid, c->s.sdrv.iscid_len, &c->scid_seq, 1};
    return 1;
  }
  *o = (srvrun_own_id){c->l.spare_cid, c->l.spare_cid_len, &c->spare_seq, 0};
  return seq == c->spare_seq && o->len;
}

/* Route o's (new) bytes to c's slot in place of the retired ones. */
static void srvrun_own_route(
    const srvrun_step_ctx* ctx, const srvrun_conn* c, const srvrun_own_id* o) {
  int slot = (int)(c - ctx->st->conns);
  if (o->primary) {
    (void)conntable_set_cid(
        ctx->st->table, WIRED_CONNTABLE_CAP, slot, o->cid, o->len);
    return;
  }
  (void)conntable_set_alt2(
      ctx->st->table, WIRED_CONNTABLE_CAP, slot, o->cid, o->len);
}

/* RFC 9000 19.15: NEW_CONNECTION_ID for o, with a fresh reset token. */
static void srvrun_own_announce(
    const srvrun_cfg* cfg, srvrun_conn* c, const srvrun_own_id* o) {
  ncid_frame f = {*o->seq, 0, o->len, {0}, {0}};
  u8         pl[48];
  bytes_memcpy(f.cid, o->cid, o->len);
  if (!cid_generate(f.token, NCID_TOKEN)) {
    return;
  }
  srvrun_send_kept(
      cfg, c, pl, ncid_encode(pl, sizeof pl, &f), "NEW_CONNECTION_ID sent\n");
}

static void srvrun_own_reissue(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_own_id* o) {
  if (!srvrun_issue_cid(ctx->cfg, o->cid, o->len)) {
    return; /* RNG failure: the peer keeps the IDs it has */
  }
  *o->seq = c->cid_next_seq++;
  srvrun_own_route(ctx, c, o);
  srvrun_own_announce(ctx->cfg, c, o);
}

static void srvrun_take_retire(
    const srvrun_step_ctx* ctx, srvrun_conn* c, u64 seq) {
  srvrun_own_id o;
  if (srvrun_retire_unissued(c, seq)) {
    srvrun_path_note_err(c, ERR_PROTOCOL_VIOLATION);
    return;
  }
  if (srvrun_own_of(c, seq, &o)) {
    srvrun_own_reissue(ctx, c, &o);
  }
}

/* This step's RETIRE_CONNECTION_ID frames (a violation closes at the
 * step's end, srvrun_close_on_cid; a repeat of a retired one is ignored). */
void srvrun_path_take_retires(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  for (usz i = 0; i < c->l.retire_rx_n; i++) {
    srvrun_take_retire(ctx, c, c->l.retire_rx[i]);
  }
  c->l.retire_rx_n = 0;
}
