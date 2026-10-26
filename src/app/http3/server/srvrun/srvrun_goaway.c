#include "app/http3/server/srvrun/srvrun_impl.h"

static int  srvrun_goaway_payload(u64 at, u64 id, wired_obuf* plb);
static void srvrun_send_wt_drain(srvrun_conn* c, int sidx);
static void srvrun_flush_wt_drain_one(srvrun_conn* c, int i);
static int  srvrun_goaway_applies(const srvrun_conn* c);
static int  srvrun_dg_queueable(const srvrun_conn* c, wired_span data);
static usz  srvrun_dg_at(const srvrun_conn* c, usz k);
static int  srvrun_dg_yields(const srvrun_conn* c, usz k, u8 urgency);
static void srvrun_dg_move(srvrun_conn* c, usz from, usz to);

/* One received datagram on a live slot: the closing state answers it
 * (srvrun_closing_rx), every other connection steps (srvrun_on_step_live). */
void srvrun_on_step(
    const srvrun_step_ctx* ctx, srvrun_conn* c, wired_mspan dg) {
  if (c->closing) {
    srvrun_closing_rx(ctx->cfg, c);
    return;
  }
  srvrun_on_step_live(ctx, c, dg);
}

/* Build the 1-RTT payload for a GOAWAY (RFC 9114 5.2) carrying id -- the
 * lowest client request stream id the server will no longer process: the H3
 * GOAWAY frame wrapped in a STREAM frame on the control stream right after
 * the SETTINGS bytes actually sent (at, wired_srvloop.ctrl_settings_len) --
 * this server sends control-stream data exactly twice (SETTINGS at
 * confirmation, GOAWAY at most once at shutdown), so no general offset
 * tracker is needed. Returns 1 with plb->len set, 0 on overflow. */
static int srvrun_goaway_payload(u64 at, u64 id, wired_obuf* plb) {
  u8           h3[16];
  usz          h3n = h3_goaway_put(h3, sizeof h3, id);
  stream_frame f;
  if (h3n == 0) {
    return 0;
  }
  f = (stream_frame){SRVRUN_CTRL_STREAM, at, h3n, h3, 0};
  return appdata_stream_frame(&f, plb);
}

/* Seal a GOAWAY (RFC 9114 5.2) on the control stream into one 1-RTT packet for
 * c, whose confirmation (SETTINGS) has already been sent at offset 0. Returns
 * 1 with out->len set, 0 if the payload cannot be built or c has no 1-RTT key
 * yet. */
int srvrun_send_goaway(const srvrun_cfg* cfg, srvrun_conn* c, wired_obuf* out) {
  u8         pl[64];
  wired_obuf plb = obuf_of(pl, sizeof pl);
  c->goaway_id   = c->l.req_next_id; /* every stream taken up keeps going */
  if (!srvrun_goaway_payload(c->l.ctrl_settings_len, c->goaway_id, &plb)) {
    return 0;
  }
  /* RFC 9000 13.3: kept and resent at the same offset until ACKed */
  if (!srvrun_seal_kept(c, pl, plb.len, out)) {
    return 0;
  }
  srvrun_send(cfg, c, wired_span_of(out->p, out->len), "GOAWAY sent\n");
  c->goaway_sent = 1;
  return 1;
}

/* draft-ietf-webtrans-http3-15 SS4.2 (WTH3-048): send session slot sidx's own
 * WT_DRAIN_SESSION capsule (empty body, wired_wt_session_drain's own
 * advisory-only doc) and apply the matching local state transition. A no-op
 * if the session was not ESTABLISHED (wired_wt_session_drain's own 0 return,
 * e.g. already draining/closed) -- nothing to drain twice. */
static void srvrun_send_wt_drain(srvrun_conn* c, int sidx) {
  u8         body[8];
  wired_obuf bob = obuf_of(body, sizeof body);
  if (!wired_wt_session_drain(srvrun_wt_slot(c, sidx))) {
    return;
  }
  if (!wtcapsule_encode_drain(&bob)) {
    return;
  }
  srvrun_send_wt_capsule(c, sidx, wired_span_of(body, bob.len), 0);
}

/* Fan WT_DRAIN_SESSION out to every active WT session slot on c -- run right
 * after c's own GOAWAY (srvrun_send_goaway), the trigger draft-ietf-webtrans-
 * http3-15 SS4.7 ties this capsule to ("a server sends WT_DRAIN_SESSION [...]
 * when [...] the connection is going away, for example, [...] GOAWAY"). */
void srvrun_send_wt_drain_all(srvrun_conn* c) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++) {
    if (srvrun_wt_is_active(c, i)) {
      srvrun_send_wt_drain(c, i);
    }
  }
}

static void srvrun_flush_wt_drain_one(srvrun_conn* c, int i) {
  if (!c->wt_drain_pending[i]) {
    return;
  }
  c->wt_drain_pending[i] = 0;
  if (srvrun_wt_is_active(c, i)) {
    srvrun_send_wt_drain(c, i);
  }
}

/* Send every session slot's pending wired_server_wt_drain_session
 * (wt_drain_pending). srvrun_send_wt_drain's own ESTABLISHED->DRAINING
 * guard keeps it to one capsule per session. */
void srvrun_flush_wt_drain(srvrun_conn* c) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++) {
    srvrun_flush_wt_drain_one(c, i);
  }
}

/* GOAWAY is HTTP/3-only (RFC 9114 5.2, a control-stream frame): an
 * hq-interop connection has no control stream to carry it, and a stray
 * stream-3 write would corrupt what an hq client saves (the same shape as
 * the SETTINGS gate in build_settings_frame). */
static int srvrun_goaway_applies(const srvrun_conn* c) {
  return c->s.sdrv.alpn == SALPN_H3 && !c->goaway_sent;
}

/* GOAWAY is owed to c once: the connection is up, confirmed (a 1-RTT key
 * exists to seal with), it negotiated h3, and no GOAWAY has gone out yet. */
int srvrun_owes_goaway(const srvrun_conn* c) {
  return c->up && c->l.hs_done_sent && srvrun_goaway_applies(c);
}

/* 1 iff data can join c's pending queue: our SETTINGS went out (RFC 9297
 * 2.1), it fits one entry, and the queue has room. */
static int srvrun_dg_queueable(const srvrun_conn* c, wired_span data) {
  if (!c->l.h3.settings_sent) {
    return 0;
  }
  return data.n <= sizeof c->dg_pending_buf[0] &&
         c->dg_pending < SRVRUN_DG_PENDING_Q;
}

/* Queue data at the tail of c's pending outbound QUIC DATAGRAMs (RFC 9221),
 * to be sent on the connection's next step (srvrun_send_pending_datagram).
 * Copies data into c->dg_pending_buf, so the caller's span need not outlive
 * this call.
 *
 * srvrun-internal for now rather than a wired_wt_session API: the
 * pending-datagram slot lives on srvrun_conn (not wired_wt_session), since
 * QUIC DATAGRAM sending is generic transport, not WebTransport-specific.
 * A future WT-specific wrapper (e.g. wired_wt_send_datagram) can call this
 * once srvrun exposes a stable per-connection handle to WT sessions; adding
 * that bridge now would be speculative (no second caller yet), and no
 * production code decides to send a datagram yet either (that needs an
 * app-facing callback hook, also not built) -- hence still test-only, same
 * situation as srvrun_test_set_shutdown above.
 *
 * Queuing itself is bounded only by the local dg_pending_buf capacity, same
 * as other frame types in this file (SRVRUN_CHUNK et al.); the peer's
 * advertised max_datagram_frame_size (RFC 9221 3) is enforced later, at send
 * time, by srvrun_send_pending_datagram.
 *
 * RFC 9297 2.1: an endpoint MUST NOT send a QUIC DATAGRAM frame before it has
 * sent its own SETTINGS_H3_DATAGRAM=1 (SETTINGS are never acked in HTTP/3, so
 * "sent" -- not "peer-observed" -- is the enforceable half of the ordering).
 * c->l.h3.settings_sent is that exact flag (set by wired_h3srv_open_control,
 * called at handshake confirmation before any response); silently drop the
 * queue request rather than invent a new error path, matching this being a
 * self-imposed ordering constraint, not a peer-facing fault.
 * ponytail: unused in the freestanding build (only tests/run.c calls this),
 * so it needs the attribute to avoid -Wunused-function under -Werror there.
 * @return 1 if queued, 0 if data.n exceeds one entry's capacity, the queue
 * is full, or our own SETTINGS have not been sent yet (RFC 9297 2.1) */
int srvrun_queue_datagram(srvrun_conn* c, wired_span data) {
  return srvrun_queue_datagram_prio(c, data, DGPRIORITY_DEFAULT);
}

/* Queue entry k's (0 = the head) index in dg_pending_buf. */
static usz srvrun_dg_at(const srvrun_conn* c, usz k) {
  return (c->dg_pending_head + k) % SRVRUN_DG_PENDING_Q;
}

/* RFC 9221 5.1: entry k-1 is less urgent than a new DATAGRAM of urgency,
 * so the new one goes ahead of it (an equal urgency keeps arrival order). */
static int srvrun_dg_yields(const srvrun_conn* c, usz k, u8 urgency) {
  return k > 0 &&
         dgpriority_higher(urgency, c->dg_pending_urg[srvrun_dg_at(c, k - 1)]);
}

/* Copy queue entry from to position to (both counted from the head). */
static void srvrun_dg_move(srvrun_conn* c, usz from, usz to) {
  usz f = srvrun_dg_at(c, from);
  usz t = srvrun_dg_at(c, to);
  bytes_memcpy(
      c->dg_pending_buf[t], c->dg_pending_buf[f], c->dg_pending_len[f]);
  c->dg_pending_len[t] = c->dg_pending_len[f];
  c->dg_pending_urg[t] = c->dg_pending_urg[f];
}

/* srvrun_queue_datagram with an urgency (RFC 9221 5.1): inserted behind
 * every queued entry at least as urgent, ahead of the rest. */
int srvrun_queue_datagram_prio(srvrun_conn* c, wired_span data, u8 urgency) {
  usz k = (usz)c->dg_pending;
  usz i;
  if (!srvrun_dg_queueable(c, data)) {
    return 0;
  }
  while (srvrun_dg_yields(c, k, urgency)) {
    srvrun_dg_move(c, k - 1, k);
    k--;
  }
  i = srvrun_dg_at(c, k);
  bytes_memcpy(c->dg_pending_buf[i], data.p, data.n);
  c->dg_pending_len[i] = data.n;
  c->dg_pending_urg[i] = urgency;
  c->dg_pending++;
  return 1;
}
