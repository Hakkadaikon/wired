#include "app/http3/server/srvrun/srvrun_impl.h"

/* draft-ietf-webtrans-http3-16 5.3/5.4/5.6: the receive side of session
 * flow control -- counting the client's streams and Stream Body bytes
 * against the limits this server advertised (control_settings.h). A stream
 * past the stream limit closes the session with WT_FLOW_CONTROL_ERROR; the
 * data check and the raises are srvrun_wtfc_grant.c's. */

static int srvrun_wtfc_over(const srvrun_wtfc* f, int bidi);
static int srvrun_wtfc_count(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, int bidi);
static void srvrun_wtfc_release(srvrun_conn* c, int owner, u64 id, u64 bytes);

/* A new session starts from the SETTINGS values. 5.1: flow control is on
 * once the peer sent any non-zero SETTINGS_WT_INITIAL_* (this server always
 * does): streams and bytes are then counted and both limits raised. The
 * stream limit is enforced only for a peer that sent a non-zero stream
 * SETTING itself -- interop: proxygen clients declare
 * SETTINGS_WT_INITIAL_MAX_DATA alone and do not count streams
 * (srvrun_wt_streams_seed_cap). */
void srvrun_wtfc_open(srvrun_conn* c, int sidx) {
  const u64* v    = c->l.peer_wt_initial;
  c->wtx.fc[sidx] = (srvrun_wtfc){
      {0, 0},
      {H3SETTINGS_WT_INIT_STREAMS_UNI_VALUE,
       H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE},
      {0, 0},
      0,
      H3SETTINGS_WT_INIT_DATA_VALUE,
      (v[0] | v[1]) != 0,
      (v[0] | v[1] | v[2]) != 0};
}

/* 1 iff the client opened more streams than the enforced limit allows. */
static int srvrun_wtfc_over(const srvrun_wtfc* f, int bidi) {
  return f->streams_on && f->opened[bidi] > f->limit[bidi];
}

/* 5.6.2: "If an endpoint receives an incoming stream for a session that
 * would exceed the advertised Maximum Streams value, it MUST close the
 * WebTransport session with a WT_FLOW_CONTROL_ERROR". Counts one client
 * stream of session sidx; 1 while the session stays open. */
static int srvrun_wtfc_count(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, int bidi) {
  srvrun_wtfc* f = &c->wtx.fc[sidx];
  f->opened[bidi] += f->data_on;
  if (!srvrun_wtfc_over(f, bidi)) {
    return 1;
  }
  srvrun_wt_rx_fail(cfg, c, sidx, WTERR_FLOW_CONTROL_ERROR);
  return 0;
}

/* A client stream just offered to session sidx (so a close resets it). */
void srvrun_wtfc_offer(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, int bidi) {
  (void)srvrun_wtfc_count(cfg, c, sidx, bidi);
}

/* Client stream id (signal length hdr) of session sidx refused before it
 * was offered: it counts against the stream limit as the client counts it
 * and -- ended at once -- is owed straight back; its bytes count once its
 * final size is known (5.4, srvrun_wtfc_pend_add). */
void srvrun_wtfc_reject(
    const srvrun_cfg* cfg,
    srvrun_conn*      c,
    int               sidx,
    int               bidi,
    u64               id,
    usz               hdr) {
  if (srvrun_wtfc_count(cfg, c, sidx, bidi)) {
    c->wtx.fc[sidx].owed[bidi] += c->wtx.fc[sidx].data_on;
    srvrun_wtfc_pend_add(
        c, id, srvrun_wt_slot(c, sidx)->connect_stream_id, hdr);
  }
}

/* The client WT bidi streams this step's srvloop pass refused for a full
 * table (wt_full): each counts against, and is owed back to, the open
 * session its signal names. shortcut: one whose first frame ended inside
 * the signal (~0) names no session and is not counted -- its client loses
 * one stream of credit; upgrade by keeping the refused stream's signal
 * bytes until they parse. */
void srvrun_wtfc_refused(const srvrun_cfg* cfg, srvrun_conn* c) {
  const wired_srvloop_wt_full* q = &c->l.wt_full;
  for (usz i = 0; i < q->n; i++) {
    int sidx = srvrun_wt_slot_by_connect_id(c, q->sid[i]);
    if (sidx >= 0) {
      srvrun_wtfc_reject(cfg, c, sidx, 1, q->id[i], q->hdr[i]);
    }
  }
  c->l.wt_full.n = 0;
}

/* 5.4: Stream Body bytes the stream carried -- its final size (or highest
 * offset, RFC 9000 4.5) less the header (signal or stream type, and session
 * id), and never less than what its window holds. */
u64 srvrun_wtfc_charge(
    const wired_srvloop* l, u64 id, usz hdr, const wired_srvloop_wt_window* w) {
  u64 seen = wired_srvloop_rx_extent(l, id);
  return u64_max(seen - u64_min(seen, hdr), w->base + w->hi);
}

/* A stream of session owner (-1: none) is freed: its bytes stay counted,
 * and a client-initiated one (RFC 9000 2.1: low bit clear) is owed back. */
static void srvrun_wtfc_release(srvrun_conn* c, int owner, u64 id, u64 bytes) {
  srvrun_wtfc* f;
  if (owner < 0) {
    return;
  }
  f = &c->wtx.fc[owner];
  f->owed[(id & 2) == 0] += (u64)((id & 1) == 0) * f->data_on;
  f->done += bytes;
}

void srvrun_wtfc_release_bidi(
    srvrun_conn* c, const wired_srvloop_wt_stream_slot* slot) {
  srvrun_wtfc_release(
      c, srvrun_wt_stream_owner(c, slot->offered, slot->wt_session_slot),
      slot->stream_id,
      srvrun_wtfc_charge(&c->l, slot->stream_id, slot->sig_len, &slot->win));
}

void srvrun_wtfc_release_uni(
    srvrun_conn* c, const wired_srvloop_wt_uni_stream_slot* slot) {
  srvrun_wtfc_release(
      c, srvrun_wt_stream_owner(c, slot->offered, slot->wt_session_slot),
      slot->stream_id,
      srvrun_wtfc_charge(&c->l, slot->stream_id, slot->type_len, &slot->win));
}
