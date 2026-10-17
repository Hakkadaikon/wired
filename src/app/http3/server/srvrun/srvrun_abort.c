#include "app/http3/server/srvrun/srvrun_impl.h"

static usz srvrun_abort_release(srvrun_conn* c, u8 i);
static u64 srvrun_incomplete_code(const srvrun_conn* c, u8 i);
static usz srvrun_abort_req(
    const srvrun_step_ctx* ctx, srvrun_conn* c, u8 i, u64 code);

/* RFC 9000 4.6: free aborted request slot i -- reading stopped, so its
 * slot and the bidi credit it held go back (srvrun_grant_streams). 1 if a
 * live slot was freed, 0 if it already was. */
static usz srvrun_abort_release(srvrun_conn* c, u8 i) {
  if (!c->l.streams[i].in_use) return 0;
  wired_srvloop_slot_release(&c->l, c->l.streams[i].stream_id);
  return 1;
}

/* RFC 9114 4.1.2 / 4.1.1: the code aborting incomplete-list slot i --
 * H3_MESSAGE_ERROR for a malformed request, else H3_REQUEST_INCOMPLETE. */
static u64 srvrun_incomplete_code(const srvrun_conn* c, u8 i) {
  return (c->l.malformed_slots >> i) & 1 ? H3_MESSAGE_ERROR
                                         : H3_REQUEST_INCOMPLETE;
}

/* Abort request slot i with code, freeing it (srvrun_abort_release). */
static usz srvrun_abort_req(
    const srvrun_step_ctx* ctx, srvrun_conn* c, u8 i, u64 code) {
  srvrun_send_wt_busy_reset(ctx->cfg, c, c->l.streams[i].stream_id, code);
  return srvrun_abort_release(c, i);
}

/* RFC 9114 4.1.1: "if the request stream ends without enough of the HTTP
 * message to provide a complete response, the server SHOULD abort its
 * response stream with the error code H3_REQUEST_INCOMPLETE" -- srvloop's
 * dispatch (route_note_incomplete) already latched each such slot in
 * incomplete_slots this step; abort every one with the same RESET_STREAM +
 * STOP_SENDING pair srvrun_reject_wt_busy uses, keyed by the stream's own
 * id (RFC 9000 2.2: a datagram may close several streams at once). */
void srvrun_abort_incomplete_reqs(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c     = &ctx->st->conns[slot];
  usz          freed = 0;
  for (usz i = 0; i < c->l.incomplete_n; i++)
    freed += srvrun_abort_req(
        ctx, c, c->l.incomplete_slots[i],
        srvrun_incomplete_code(c, c->l.incomplete_slots[i]));
  srvrun_grant_streams(ctx, c, srvrun_stream_limit_base(ctx), freed);
}

/* RFC 9114 7.2.5/7.2.8 (9114-067/9114-073): a request stream carried
 * PUSH_PROMISE or an HTTP/2-only reserved frame type -- srvloop's dispatch
 * (route_note_frame_unexpected) already detected it and latched the slot in
 * frame_unexpected_slots this step; abort it with H3_FRAME_UNEXPECTED, same
 * RESET_STREAM + STOP_SENDING pair and slot release as
 * srvrun_abort_incomplete_reqs. */
void srvrun_abort_frame_unexpected_reqs(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c     = &ctx->st->conns[slot];
  usz          freed = 0;
  for (usz i = 0; i < c->l.frame_unexpected_n; i++)
    freed += srvrun_abort_req(
        ctx, c, c->l.frame_unexpected_slots[i], H3_FRAME_UNEXPECTED);
  srvrun_grant_streams(ctx, c, srvrun_stream_limit_base(ctx), freed);
}

/* Return r's borrowed wired_srvbigbuf row to the pool, if it holds one.
 * Clears the index: a released slot that kept its row number would hand it
 * back AGAIN on the next release sweep (srvrun_free_bigbuf_rows runs over
 * every resp[] at teardown), yanking the row out from under whichever
 * connection had legitimately re-claimed it -- two live responses then
 * share one row and both transmit whatever was written last. */
void srvrun_resp_release_bigbuf(wired_srvrun_env* env, srvrun_resp* r) {
  if (r->bigbuf_row < 0) return;
  wired_srvbigbuf_release(&env->bigbuf, r->bigbuf_row);
  r->bigbuf_row = -1;
}

/* 1 while r is a live streaming response the refill loop must keep fed. */
int srvrun_resp_streaming_live(const srvrun_resp* r) {
  return r->in_use && r->streaming;
}

/* Bytes the next refill may write: the reclaimed room, capped at the ring
 * wrap so one handler write stays contiguous in storage. */
usz srvrun_resp_refill_take(const srvrun_resp* r, usz room) {
  usz take = r->ring_cap - r->sess.q.len % r->ring_cap;
  return take < room ? take : room;
}

/* Run the handler for the next body chunk straight into r's ring (at most
 * take bytes, contiguous at the ring's write position) and extend the live
 * sendsess over what it wrote. */
void srvrun_resp_refill_write(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    int                    slot,
    srvrun_resp*           r,
    usz                    take) {
  u8*        base = srvrun_resp_storage_ro(ctx, slot, c, r);
  wired_obuf body = obuf_of(
      base + (usz)(r->sess.q.p - base) + r->sess.q.len % r->ring_cap, take);
  wired_http_exchange x = {0};
  x.req                 = &r->stream_req;
  x.offset              = r->stream_off;
  x.body                = &body;
  srvrun_call_handler(ctx, &x);
  wired_sendsess_extend(&r->sess, body.len);
  r->stream_off += body.len;
  r->streaming = x.more != 0;
}
