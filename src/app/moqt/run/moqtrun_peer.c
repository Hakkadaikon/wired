#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_peer_rx_reset(wired_moqtrun_peer* p);
static void moqtrun_peer_life_reset(wired_moqtrun_peer* p);
static void moqtrun_init_peer(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_wt_session*   s,
    int                 ver,
    int                 legacy,
    int                 raw);
static int  moqtrun_negotiated_ver(wired_span protocol);
static int  moqtrun_legacy_token(wired_span protocol);
static void moqtrun_refuse_session(wired_moqt_hub* hub, wired_wt_session* s);

static void moqtrun_peer_rx_reset(wired_moqtrun_peer* p) {
  p->peer_ctl_set       = 0;
  p->peer_ctl_stream_id = 0;
  p->setup_recv         = 0;
  p->rx_sid             = 0;
  p->rx                 = 0;
  p->peer_ctl_asm.n     = 0;
  p->peer_ctl_asm.at    = 0;
  p->peer_ctl_asm.skip  = 0;
  p->peer_impl_len      = 0;
  p->peer_has_impl      = 0;
}

static void moqtrun_peer_life_reset(wired_moqtrun_peer* p) {
  p->hold_len          = 0;
  p->early_n           = 0;
  p->pre_n             = 0;
  p->goaway_deadline   = (u64)-1;
  p->goaway_flushed_at = 0;
  p->closing           = 0;
  p->wt_drained        = 0;
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++) {
    p->tracks[t].in_use = 0;
  }
  moqsess_init(&p->sess);
  moqtss_sess_reset(&p->ssts); /* SSTS (moqtssts_run.c) */
}

/* Initializes a freshly allocated peer slot for s and sends its SETUP,
 * split out of wired_moqt_on_session to keep that function's own branch
 * count at the CCN gate. SETUP goes out on send_bufs[0]: that slot becomes
 * "armed" (open_bidi_stream holds the same view/ACK contract as
 * stream_send, per srvrun.h), so armed_idx starts at 0 and every reply
 * queued afterward goes to the OTHER slot (moqtrun_queue_reply's doc). */
static void moqtrun_init_peer(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_wt_session*   s,
    int                 ver,
    int                 legacy,
    int                 raw) {
  p->in_use   = 1;
  p->wt       = s;
  p->ver      = ver;
  p->legacy   = (u8)legacy;
  p->raw      = (u8)raw;
  p->join_seq = hub->join_seq_next++;
  moqtrun_peer_ctl_reset(p);
  moqtrun_peer_rx_reset(p);
  moqtrun_peer_life_reset(p);
  moqtrun_ctl_open(hub, p);
}

/* moqver_find's -1 (a token the table does not list) falls back to
 * draft-19, the same conservative default as an empty token. */
static int moqtrun_negotiated_ver(wired_span protocol) {
  int ver = moqver_find(protocol);
  return ver < 0 ? MOQVER_D19 : ver;
}

/* draft-19 3.3 binding choice: only a negotiated moqt-NN token selects
 * the uni control-stream pair; an empty token (a browser cannot
 * negotiate a WT subprotocol) or an unlisted one -- no moqt-NN
 * agreement with the peer -- keeps the pre-d17 single bidi. */
static int moqtrun_legacy_token(wired_span protocol) {
  return protocol.n == 0 || moqver_find(protocol) < 0;
}

void wired_moqt_on_session(
    void* app_ctx, wired_wt_session* s, wired_span path, wired_span protocol) {
  (void)path;
  wired_moqt_hub* hub = (wired_moqt_hub*)app_ctx;
  int             ver = moqtrun_negotiated_ver(protocol);
  /* srvrun's wt_on_session doc promises "fires once after [the 2xx] is
   * built", but a duplicate Extended CONNECT can still reach the app layer
   * (e.g. a retried/speculative one) -- draft 3.3 permits only one control
   * stream per peer per session, so a second SETUP here would itself be the
   * protocol violation this hub is supposed to prevent, not just redundant
   * work. Guard by session identity: a callback for an already-tracked s is
   * a no-op instead of allocating a second peer slot and sending SETUP
   * twice on the same WT session. */
  if (moqtrun_find_by_wt(hub, s)) {
    return;
  }
  wired_moqtrun_peer* p = moqtrun_alloc(hub);
  if (!p) {
    return;
  }
  moqtrun_init_peer(hub, p, s, ver, moqtrun_legacy_token(protocol), 0);
}

/* Review F4 (MoqtRawConn): a raw session the hub cannot track is closed
 * at once, INTERNAL_ERROR (-22 6.6), not left for the idle sweep. */
static void moqtrun_refuse_session(wired_moqt_hub* hub, wired_wt_session* s) {
  if (!hub->io.close_session) {
    return;
  }
  hub->io.close_session(
      s, WIRED_MOQTRUN_CLOSE_INTERNAL_ERROR, wired_span_of(0, 0));
}

/* draft-ietf-moq-transport-22 6.2 (-18/-19 3.1): on native QUIC the ALPN
 * moqt-NN is the version negotiation, and the control streams are the
 * uni pair exactly as on WT with a negotiated token (6.3/6.4) -- so never
 * legacy. Same duplicate guard as wired_moqt_on_session. */
void wired_moqt_on_session_raw(
    void* app_ctx, wired_wt_session* s, wired_span alpn) {
  wired_moqt_hub* hub = (wired_moqt_hub*)app_ctx;
  if (moqtrun_find_by_wt(hub, s)) {
    return;
  }
  wired_moqtrun_peer* p = moqtrun_alloc(hub);
  if (!p) {
    moqtrun_refuse_session(hub, s);
    return;
  }
  moqtrun_init_peer(hub, p, s, moqtrun_negotiated_ver(alpn), 0, 1);
}
