#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_arm_h3_resp_framed(
    const srvrun_step_ctx*     ctx,
    srvrun_conn*               c,
    int                        slot,
    srvrun_resp*               r,
    u8*                        st,
    const wired_http_exchange* x,
    u64                        total_len);
static int srvrun_copy_hdr_part(
    srvrun_resp* r, usz* off, const u8* base, u16* pos, u16 len);
static int srvrun_copy_hdr(
    srvrun_resp* r, usz* off, const u8* base, wired_h3reqdrive_hdr* h);

static void srvrun_arm_h3_resp_framed(
    const srvrun_step_ctx*     ctx,
    srvrun_conn*               c,
    int                        slot,
    srvrun_resp*               r,
    u8*                        st,
    const wired_http_exchange* x,
    u64                        total_len) {
  u8                pre[SRVRUN_RESP_HDR_ROOM];
  wired_obuf        pob  = obuf_of(pre, sizeof pre);
  const wired_obuf* body = x->body;
  usz               off;
  if (!srvrun_h3_resp_prefix(c, x, total_len, &pob)) {
    r->arm_failed = 1; /* the app's fields overflow the prefix room */
    return;
  }
  off = SRVRUN_RESP_HDR_ROOM - pob.len;
  bytes_put(
      wired_mspan_of(st, SRVRUN_RESP_HDR_ROOM), &off,
      wired_span_of(pre, pob.len));
  st = srvrun_resp_shrink_to_fixed(
      ctx, slot, c, r, st + SRVRUN_RESP_HDR_ROOM - pob.len,
      pob.len + body->len);
  wired_sendsess_arm(&r->sess, st, pob.len + body->len, srvrun_mps(c));
}

/* RFC 9114 4.1: frame+arm round 0 (the only arm a response ever gets now
 * -- a streaming response's later bytes continue the same DATA frame via
 * the ring refill's extend, srvrun_resp_refill, never a re-arm). */
void srvrun_arm_h3_resp(
    const srvrun_step_ctx*     ctx,
    srvrun_conn*               c,
    int                        slot,
    srvrun_resp*               r,
    u8*                        st,
    const wired_http_exchange* x,
    u64                        total_len) {
  r->stream_h3_framed = 1;
  srvrun_arm_h3_resp_framed(ctx, c, slot, r, st, x, total_len);
}

/* Copy one view of r->stream_req into r's own scratch at *off (capped at
 * what is left of it) and re-point the view there. An absent view (0, e.g.
 * no :protocol / origin) stays 0 so the handler still reads it as absent. */
void srvrun_scratch_view(srvrun_resp* r, usz* off, const u8** p, usz* len) {
  usz n;
  if (!*p) {
    return;
  }
  n = (usz)u64_min(*len, sizeof r->stream_req_scratch - *off);
  bytes_memcpy(r->stream_req_scratch + *off, *p, n);
  *p   = r->stream_req_scratch + *off;
  *len = n;
  *off += n;
}

/* Move one recorded header position (*pos, len octets of base) into r's
 * scratch at *off. 0 if it no longer fits. */
static int srvrun_copy_hdr_part(
    srvrun_resp* r, usz* off, const u8* base, u16* pos, u16 len) {
  if (len > sizeof r->stream_req_scratch - *off) {
    return 0;
  }
  bytes_memcpy(r->stream_req_scratch + *off, base + *pos, len);
  *pos = (u16)*off;
  *off += len;
  return 1;
}

static int srvrun_copy_hdr(
    srvrun_resp* r, usz* off, const u8* base, wired_h3reqdrive_hdr* h) {
  return srvrun_copy_hdr_part(r, off, base, &h->name_off, h->name_len) &&
         srvrun_copy_hdr_part(r, off, base, &h->value_off, h->value_len);
}

/* Move the recorded request headers after the views; those that no longer
 * fit the copy's scratch are dropped from the end. */
void srvrun_copy_stream_hdrs(srvrun_resp* r, usz off) {
  wired_h3reqdrive_req* q    = &r->stream_req;
  const u8*             base = q->hdr_base;
  usz                   i    = 0;
  while (i < q->hdr_count && srvrun_copy_hdr(r, &off, base, &q->hdrs[i])) {
    i++;
  }
  q->hdr_count = i;
  q->hdr_base  = r->stream_req_scratch;
}
