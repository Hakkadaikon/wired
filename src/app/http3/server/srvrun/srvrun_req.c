#include "app/http3/server/srvrun/srvrun_impl.h"

static usz wt_slots_in_use(const srvrun_conn* c);
static u64 srvrun_req_slot_ceiling(const wired_srvloop_stream_slot* slot);
static int srvrun_req_any_streaming(const srvrun_conn* c);
static int srvrun_conn_credit_live(const srvrun_conn* c);
static u64 srvrun_wt_connect_slack(srvrun_conn* c);
static int srvrun_conn_credit_moving(const srvrun_conn* c, u64 slack);
static u64 srvrun_qenc_rx_ceiling(const srvrun_conn* c);
static int srvrun_qenc_credit_due(const srvrun_conn* c, u64 ceiling);

/* RFC 9000 4.1: how many WT bidi/uni slots on c are currently in use -- the
 * connection-wide MAX_DATA ceiling needs one buffer's worth of slack PER
 * open slot (each slot's own MAX_STREAM_DATA independently opens up to a
 * full WIRED_SRVLOOP_WT_BUF_CAP ahead of what it delivered), not a single
 * buffer's worth shared across every slot -- undercounting this starved
 * every slot but one down to the connection ceiling once several were
 * active at once (found via a real webtransport-go interop run: streams
 * stalled hard the moment their combined MAX_STREAM_DATA ceilings outran a
 * one-buffer-wide MAX_DATA). */
usz srvrun_wt_bidi_slots_in_use(const srvrun_conn* c) {
  usz n = 0;
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    if (c->l.wt_streams[i].in_use) n++;
  return n;
}

usz srvrun_wt_uni_slots_in_use(const srvrun_conn* c) {
  usz n = 0;
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++)
    if (c->l.wt_uni_streams[i].in_use) n++;
  return n;
}

static usz wt_slots_in_use(const srvrun_conn* c) {
  return srvrun_wt_bidi_slots_in_use(c) + srvrun_wt_uni_slots_in_use(c);
}

/* A request slot whose body is still streaming (srvloop's body window). */
int srvrun_req_credit_live(const wired_srvloop_stream_slot* slot) {
  return slot->in_use && slot->body.on && slot->body.state == BODYWIN_OPEN;
}

/* One request slot's share of the MAX_DATA ceiling: the body bytes its
 * window already consumed, plus the window itself while it streams. */
static u64 srvrun_req_slot_ceiling(const wired_srvloop_stream_slot* slot) {
  u64 open = srvrun_req_credit_live(slot) ? BODYWIN_CAP : 0;
  return slot->in_use ? slot->body.base + open : 0;
}

/* RFC 9000 4.1: the request side of the connection ceiling -- streamed body
 * bytes of every released slot plus each live slot's share. */
u64 srvrun_req_rx_ceiling(const srvrun_conn* c) {
  u64 total = c->l.req_body_released;
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++)
    total += srvrun_req_slot_ceiling(&c->l.streams[i]);
  return total;
}

/* 1 while some request body streams. */
static int srvrun_req_any_streaming(const srvrun_conn* c) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++)
    if (srvrun_req_credit_live(&c->l.streams[i])) return 1;
  return 0;
}

/* The connection credit moves while a WT slot or a streamed request body
 * is consuming it. */
static int srvrun_conn_credit_live(const srvrun_conn* c) {
  return srvrun_wt_any_slot_in_use(c) || srvrun_req_any_streaming(c);
}

/* RFC 9000 4.1: one window of slack per active WT session whose CONNECT
 * stream still reassembles capsules -- that stream's own MAX_STREAM_DATA
 * opens a window ahead (srvrun_wt_rx_capsules_one), so the connection
 * ceiling must too. Its consumed bytes (window base) are already in
 * srvrun_req_rx_ceiling. */
static u64 srvrun_wt_connect_slack(srvrun_conn* c) {
  u64 n = 0;
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++)
    n += srvrun_wt_rx_slot(c, i) ? BODYWIN_CAP : 0;
  return n;
}

/* The connection credit moves: capsules flow on a CONNECT stream (slack),
 * the peer's encoder stream consumed bytes, or srvrun_conn_credit_live. */
static int srvrun_conn_credit_moving(const srvrun_conn* c, u64 slack) {
  return slack || c->l.h3.qenc_rx.base || srvrun_conn_credit_live(c);
}

/* RFC 9000 4.1: the claimed encoder stream's consumed bytes plus its
 * window (qdyn_encrx_credit) -- re-granted without bound, so they must sit
 * under the connection ceiling too. */
static u64 srvrun_qenc_rx_ceiling(const srvrun_conn* c) {
  const qdyn_encrx* rx = &c->l.h3.qenc_rx;
  return rx->type_len ? qdyn_encrx_credit(rx) : 0;
}

/* RFC 9000 4.1/19.9: re-grant this connection's receive credit once its total
 * WT and streamed request-body progress has advanced enough past what was last
 * advertised -- the connection-wide counterpart of srvrun_grant_stream_
 * credit, using the same ceiling shape (delivered + one buffer's worth of
 * slack) so raising every open stream's own window never outruns the shared
 * connection ceiling. A no-op while neither a WT slot nor a streamed request
 * body nor a capsule-carrying CONNECT stream is live
 * (srvrun_conn_credit_moving). The ceiling counts a CONNECT stream's
 * consumed capsule bytes (its window base, srvrun_req_rx_ceiling) plus its
 * window (srvrun_wt_connect_slack), and the peer's encoder stream
 * (srvrun_qenc_rx_ceiling). ponytail: control-stream and buffered request
 * bytes are not counted; the initial 10 MB (STP_DEFAULT_MAX_DATA) covers
 * them. */
void srvrun_grant_conn_credit(const srvrun_cfg* cfg, srvrun_conn* c) {
  u64 slack   = srvrun_wt_connect_slack(c);
  u64 ceiling = c->wt_rx_reaped_total + srvrun_wt_rx_delivered_total(c) +
                (u64)wt_slots_in_use(c) * WIRED_SRVLOOP_WT_BUF_CAP +
                srvrun_req_rx_ceiling(c) + slack + srvrun_qenc_rx_ceiling(c);
  if (!srvrun_conn_credit_moving(c, slack)) return;
  if (!srvrun_wt_credit_stream_due(ceiling, c->rx_max_data_advertised)) return;
  srvrun_send_max_data(cfg, c, ceiling);
  c->rx_max_data_advertised = ceiling;
}

/* draft-ietf-webtrans-http3-15 4.3 / RFC 9000 4.1: after a step's reassembly/
 * delivery/window-slide passes, re-grant flow-control credit for every WT
 * slot whose window has advanced (srvrun_grant_wt_slot_credit/_uni), then the
 * connection-wide ceiling once (srvrun_grant_conn_credit) -- called once per
 * step regardless of whether this step itself delivered anything, so a
 * connection with an idle WT slot still eventually catches up after a burst
 * a few steps earlier. */
/* RFC 9000 4.1: due once the encoder window's end passed both the initial
 * credit and the last grant. */
static int srvrun_qenc_credit_due(const srvrun_conn* c, u64 ceiling) {
  return ceiling > QDYN_ENCRX_CAP && ceiling > c->qenc_credit_advertised;
}

/* RFC 9000 4.1 / 19.10, RFC 9204 4.2: re-grant the peer's encoder stream
 * credit to the end of its reassembly window as instructions are consumed
 * (qdyn_encrx_credit), so the stream is never capped at its initial credit
 * and never sends past what the window holds. */
void srvrun_grant_qenc_credit(const srvrun_cfg* cfg, srvrun_conn* c) {
  const qdyn_encrx* rx      = &c->l.h3.qenc_rx;
  u64               ceiling = qdyn_encrx_credit(rx);
  if (!rx->type_len || !srvrun_qenc_credit_due(c, ceiling)) return;
  srvrun_send_max_stream_data(cfg, c, rx->stream_id, ceiling);
  c->qenc_credit_advertised = ceiling;
}
