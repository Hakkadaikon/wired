#include "app/http3/server/srvrun/srvrun_impl.h"

static qpackenc_state* srvrun_qenc_active(srvrun_conn* c);
static void            srvrun_qenc_send_insert(
    srvrun_conn* c, const qpackenc_status_result* ins);

/* Reject this Extended CONNECT with 403 (a present but malformed Origin, or
 * one the app's wt_origin_check refused) without establishing a session. */
void srvrun_reject_wt(
    wired_srvrun_env* env, int slot, srvrun_conn* c, srvrun_resp* r) {
  srvrun_start_wt_status(env, slot, c, r, 403, 0);
}

/* r's storage row for this response: the fixed per-(conn,stream) respstore
 * row (WIRED_SRVRUN_RESP_MAX = 16KB, SRVRUN_RESP_HDR_ROOM reserved at the
 * front for the framed HEADERS prefix), or -- when the app handler needs
 * more room than that -- a claimed wired_srvbigbuf row (srvbigbuf.h),
 * reserving the same HDR_ROOM prefix at its own front. Pool exhaustion
 * falls back to the fixed row (its cap simply bounds the handler's write,
 * same as before this pool existed): a body that then overflows the fixed
 * row is truncated by the handler's own wired_obuf cap, not a new failure
 * mode. r->bigbuf_row records which storage was used, -1 for the fixed row,
 * so srvrun_resp_reap knows whether to release a pool row later. A
 * streaming response's later rounds (r->bigbuf_row already >= 0) reuse that
 * SAME row instead of re-claiming -- a second claim here would either grab
 * a different pool row (silently orphaning round 0's, since only one index
 * is tracked) or, if the pool is momentarily full, hand back 0 and corrupt
 * an otherwise-fine ongoing stream. */
u8* srvrun_resp_storage(
    const srvrun_step_ctx* ctx, int slot, srvrun_conn* c, srvrun_resp* r) {
  u8* fixed = ctx->cfg->env->respstore[slot][srvrun_resp_index(c, r)];
  u8* big;
  if (r->bigbuf_row >= 0)
    return wired_srvbigbuf_row(&ctx->cfg->env->bigbuf, r->bigbuf_row);
  big = wired_srvbigbuf_claim(&ctx->cfg->env->bigbuf, &r->bigbuf_row);
  return big ? big : fixed;
}

/* Bytes available in st for body_out (past the HDR_ROOM prefix), matching
 * whichever storage srvrun_resp_storage chose. */
usz srvrun_resp_storage_cap(const srvrun_resp* r) {
  return (r->bigbuf_row >= 0 ? WIRED_SRVBIGBUF_ROW_CAP
                             : WIRED_SRVRUN_RESP_MAX) -
         SRVRUN_RESP_HDR_ROOM;
}

/* The storage row r is armed over, WITHOUT the claim side effect
 * (srvrun_resp_storage claims a pool row for bigbuf_row < 0) -- the
 * read-only companion for callers that only need the existing base. */
u8* srvrun_resp_storage_ro(
    const srvrun_step_ctx* ctx, int slot, srvrun_conn* c, srvrun_resp* r) {
  if (r->bigbuf_row >= 0)
    return wired_srvbigbuf_row(&ctx->cfg->env->bigbuf, r->bigbuf_row);
  return ctx->cfg->env->respstore[slot][srvrun_resp_index(c, r)];
}

/* Full byte size of the row srvrun_resp_storage chose. */
usz srvrun_resp_row_size(const srvrun_resp* r) {
  return r->bigbuf_row >= 0 ? WIRED_SRVBIGBUF_ROW_CAP : WIRED_SRVRUN_RESP_MAX;
}

/* If r's body ended up small enough for the fixed respstore row after all
 * (the common case: most responses are far under 16KB), copy it there and
 * release the pool row immediately -- pool rows are scarce (2 total) and a
 * response that never needed one should not hold one for its whole
 * lifetime. body/pre are already-framed bytes at st (HDR_ROOM prefix +
 * body); total is their combined length. */
u8* srvrun_resp_shrink_to_fixed(
    const srvrun_step_ctx* ctx,
    int                    slot,
    srvrun_conn*           c,
    srvrun_resp*           r,
    u8*                    st,
    usz                    total) {
  u8* fixed;
  if (r->bigbuf_row < 0 || total > WIRED_SRVRUN_RESP_MAX) return st;
  fixed = ctx->cfg->env->respstore[slot][srvrun_resp_index(c, r)];
  bytes_memcpy(fixed, st, total);
  wired_srvbigbuf_release(&ctx->cfg->env->bigbuf, r->bigbuf_row);
  r->bigbuf_row = -1;
  return fixed;
}

/* quic-interop-runner's hq-interop (HTTP/0.9 over QUIC, see hq09.h): the
 * response is the handler's body bytes verbatim, no HEADERS/DATA framing
 * (RFC 9114 4.1 doesn't apply -- there is no HTTP/3 on this connection).
 * Arms directly over the body already written at st + HDR_ROOM, skipping
 * the H3 prefix build/shrink-to-fixed dance that assumes a framed
 * response. Every round (streaming or not) takes this same path: hq-interop
 * never frames, so there is no first-round-only prefix to skip on later
 * rounds. */
void srvrun_arm_hq09_resp(
    const srvrun_conn* c, srvrun_resp* r, u8* st, const wired_obuf* body) {
  wired_sendsess_arm(
      &r->sess, st + SRVRUN_RESP_HDR_ROOM, body->len, srvrun_mps(c));
}

/* RFC 9114 4.1: frame the handler's body as HEADERS+DATA (h3resp_prefix)
 * ahead of it, then arm over prefix+body. total_len is the DATA frame's
 * declared length (the full streaming response's total size,
 * not just this round's body -- HTTP/3 commits to one length upfront and
 * every later round's bytes are additional payload of that same frame, so
 * only round 0 ever calls this). Split out of srvrun_start_app_resp so
 * hq-interop's un-framed sibling can skip this whole shape (CCN). */
/* c's own qpackenc_state, or 0 while the QPACK encoder stream (RFC 9204 4.2)
 * has not been opened yet -- h3resp_prefix_field_qenc/h3resp_encode_headers_
 * field_qenc both treat a null qenc as "no dynamic table", the pre-existing
 * static-or-literal-only behavior, so a response built before the encoder
 * stream opens never references table state the peer's decoder was never
 * told about (RFC 9204 2.1.4/4.3.3). */
static qpackenc_state* srvrun_qenc_active(srvrun_conn* c) {
  return c->qenc_stream_opened ? &c->l.h3.qenc : 0;
}

/* RFC 9204 4.3.3/4.4.1: forward a fresh Insert instruction (ins->insert_len
 * bytes) to the QPACK encoder stream's wtsend slot, then record that the
 * field section it was generated for was sent (qpackenc_note_sent) so
 * pending_acks tracks it. A no-op when there is nothing to send (insert_len
 * == 0, the common case: an entry already lived in the dynamic table or
 * capacity fell back to literal) or the encoder stream is not open. */
static void srvrun_qenc_send_insert(
    srvrun_conn* c, const qpackenc_status_result* ins) {
  srvrun_wtsend* w = srvrun_plumbing_wtsend(
      c, c->qenc_stream_opened, c->qenc_wtsend_slot, SRVRUN_QENC_STREAM);
  if (!w) return;
  if (ins->insert_len)
    srvrun_wtsend_stage_round(
        c, w, wired_span_of(ins->insert_instr, ins->insert_len), 0);
  qpackenc_note_sent(&c->l.h3.qenc, ins->required_insert_count);
}

/* Build x's response prefix (HEADERS + DATA header for total_len body
 * bytes) into pob and forward any QPACK Insert it generated. Returns 0 when
 * the app's fields overflow pob. */
int srvrun_h3_resp_prefix(
    srvrun_conn*               c,
    const wired_http_exchange* x,
    u64                        total_len,
    wired_obuf*                pob) {
  h3resp_fields          f = {x->fields, x->field_count};
  qpackenc_status_result ins;
  if (!h3resp_prefix_fields_qenc(
          srvrun_http_status(x), x->content_type, total_len, f,
          srvrun_qenc_active(c), &ins, pob))
    return 0;
  srvrun_qenc_send_insert(c, &ins);
  return 1;
}
