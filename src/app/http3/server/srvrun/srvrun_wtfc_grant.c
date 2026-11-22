#include "app/http3/server/srvrun/srvrun_impl.h"

/* draft-ietf-webtrans-http3-16 5.4/5.6: the data check and the credit side
 * of session flow control (srvrun_wtfc.c counts streams). WT_MAX_STREAMS /
 * WT_MAX_DATA ride the CONNECT stream's send slot (srvrun_send_wt_capsule),
 * which retransmits lost bytes (RFC 9000 13.3); a capsule the slot cannot
 * take now stays owed and goes out on a later step or tick. */

static int srvrun_wtfc_owns_bidi(
    const wired_srvloop_wt_stream_slot* s, int sidx);
static int srvrun_wtfc_owns_uni(
    const wired_srvloop_wt_uni_stream_slot* s, int sidx);
static u64  srvrun_wtfc_rx_bidi(const srvrun_conn* c, int sidx);
static u64  srvrun_wtfc_rx_uni(const srvrun_conn* c, int sidx);
static u64  srvrun_wtfc_used_of(const srvrun_conn* c, int sidx);
static int  srvrun_wtfc_stage(srvrun_conn* c, int sidx, const wired_obuf* bob);
static void srvrun_wtfc_raise_streams(srvrun_conn* c, int sidx, int bidi);
static void srvrun_wtfc_raise_data(srvrun_conn* c, int sidx, u64 used);
static void srvrun_wtfc_raise(srvrun_conn* c, int sidx);
static int  srvrun_wtfc_counted(const srvrun_conn* c, int sidx);
static void srvrun_wtfc_step_one(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx);

static int srvrun_wtfc_owns_bidi(
    const wired_srvloop_wt_stream_slot* s, int sidx) {
  return s->in_use && s->offered && s->wt_session_slot == sidx;
}

static int srvrun_wtfc_owns_uni(
    const wired_srvloop_wt_uni_stream_slot* s, int sidx) {
  return s->in_use && s->offered && s->wt_session_slot == sidx;
}

/* Stream Body bytes received on the live bidi streams session sidx owns
 * (the receive-accounting lookup only for those). */
static u64 srvrun_wtfc_rx_bidi(const srvrun_conn* c, int sidx) {
  u64 rx = 0;
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++) {
    const wired_srvloop_wt_stream_slot* s = &c->l.wt_streams[i];
    if (srvrun_wtfc_owns_bidi(s, sidx)) {
      rx += srvrun_wtfc_charge(&c->l, s->stream_id, s->sig_len, &s->win);
    }
  }
  return rx;
}

/* Same as srvrun_wtfc_rx_bidi, over the uni table. */
static u64 srvrun_wtfc_rx_uni(const srvrun_conn* c, int sidx) {
  u64 rx = 0;
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++) {
    const wired_srvloop_wt_uni_stream_slot* s = &c->l.wt_uni_streams[i];
    if (srvrun_wtfc_owns_uni(s, sidx)) {
      rx += srvrun_wtfc_charge(&c->l, s->stream_id, s->type_len, &s->win);
    }
  }
  return rx;
}

/* Session sidx's consumed Stream Body bytes: its freed streams plus what
 * the app took from every live stream it owns. */
static u64 srvrun_wtfc_used_of(const srvrun_conn* c, int sidx) {
  u64 used = c->wtx.fc[sidx].done;
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++) {
    const wired_srvloop_wt_stream_slot* s = &c->l.wt_streams[i];
    used += (u64)srvrun_wtfc_owns_bidi(s, sidx) * s->delivered_len;
  }
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++) {
    const wired_srvloop_wt_uni_stream_slot* s = &c->l.wt_uni_streams[i];
    used += (u64)srvrun_wtfc_owns_uni(s, sidx) * s->delivered_len;
  }
  return used;
}

/* Stage the capsule encoded in bob (len 0: encoding failed); 1 iff staged. */
static int srvrun_wtfc_stage(srvrun_conn* c, int sidx, const wired_obuf* bob) {
  return bob->len &&
         srvrun_send_wt_capsule(c, sidx, wired_span_of(bob->p, bob->len), 0);
}

/* 5.6.2: WT_MAX_STREAMS = the limit plus every client stream ended since. */
static void srvrun_wtfc_raise_streams(srvrun_conn* c, int sidx, int bidi) {
  srvrun_wtfc* f = &c->wtx.fc[sidx];
  u8           body[16];
  wired_obuf   bob = obuf_of(body, sizeof body);
  u64          v   = f->limit[bidi] + f->owed[bidi];
  if (!f->owed[bidi]) {
    return;
  }
  (void)wtcapsule_encode_max_streams(&bob, bidi, v);
  if (srvrun_wtfc_stage(c, sidx, &bob)) {
    f->limit[bidi] = v;
    f->owed[bidi]  = 0;
  }
}

/* 5.6.4: WT_MAX_DATA = consumed + one initial window, once that moves the
 * limit by half a window (the batching of RFC 9000 4.2). */
static void srvrun_wtfc_raise_data(srvrun_conn* c, int sidx, u64 used) {
  srvrun_wtfc* f = &c->wtx.fc[sidx];
  u8           body[16];
  wired_obuf   bob = obuf_of(body, sizeof body);
  u64          v   = used + H3SETTINGS_WT_INIT_DATA_VALUE;
  if (v < f->max_data + H3SETTINGS_WT_INIT_DATA_VALUE / 2) {
    return;
  }
  (void)wtcapsule_encode_max_data(&bob, v);
  if (srvrun_wtfc_stage(c, sidx, &bob)) {
    f->max_data = v;
  }
}

/* 5.6: "Endpoints SHOULD send WT_MAX_DATA and WT_MAX_STREAMS capsules as
 * they consume data or close streams". */
static void srvrun_wtfc_raise(srvrun_conn* c, int sidx) {
  srvrun_wtfc_raise_streams(c, sidx, 0);
  srvrun_wtfc_raise_streams(c, sidx, 1);
  srvrun_wtfc_raise_data(c, sidx, srvrun_wtfc_used_of(c, sidx));
}

/* 1 while session sidx is open with flow control on (srvrun_wtfc_open). */
static int srvrun_wtfc_counted(const srvrun_conn* c, int sidx) {
  return srvrun_wt_is_active(c, sidx) && c->wtx.fc[sidx].data_on;
}

/* 5.6.4: "If an endpoint receives Stream Body data in excess of this
 * limit, it MUST close the WebTransport session with a
 * WT_FLOW_CONTROL_ERROR"; otherwise raise what is due. */
static void srvrun_wtfc_step_one(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx) {
  u64 rx;
  if (!srvrun_wtfc_counted(c, sidx)) {
    return;
  }
  rx = c->wtx.fc[sidx].done + srvrun_wtfc_rx_bidi(c, sidx) +
       srvrun_wtfc_rx_uni(c, sidx);
  if (rx > c->wtx.fc[sidx].max_data) {
    srvrun_wt_rx_fail(cfg, c, sidx, WTERR_FLOW_CONTROL_ERROR);
    return;
  }
  srvrun_wtfc_raise(c, sidx);
}

/* Per received step, after the stream passes: the streams the table
 * refused, the refused streams whose final size is now known, then every
 * open session in turn. */
void srvrun_wtfc_step(const srvrun_cfg* cfg, srvrun_conn* c) {
  srvrun_wtfc_refused(cfg, c);
  srvrun_wtfc_settle(c);
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++) {
    srvrun_wtfc_step_one(cfg, c, i);
  }
}

/* Per tick: the raises alone, so one the send slot refused goes out with
 * no further packet from the client (it may wait silently for credit). */
void srvrun_wtfc_flush(srvrun_conn* c) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++) {
    if (srvrun_wtfc_counted(c, i)) {
      srvrun_wtfc_raise(c, i);
    }
  }
}
