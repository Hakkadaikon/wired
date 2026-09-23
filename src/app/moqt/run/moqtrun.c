#include "app/moqt/run/moqtrun.h"

#include "app/moqt/ctl/moqctl.h"
#include "app/moqt/data/moqdata.h"
#include "app/moqt/dgram/moqdg.h"
#include "app/moqt/vi/moqvi.h"
#include "common/bytes/util/bytes.h"

/* draft-ietf-moq-transport-19 hub relay. See moqtrun.h for the
 * design summary; each function here stays a thin dispatch over the
 * vi/kvp/ctl/data/sess domains, never reimplementing their codecs. */

/* ===================== peer table ===================== */

static int moqtrun_peer_matches_wt(
    const wired_moqtrun_peer* p, const wired_wt_session* s) {
  return p->in_use && p->wt == s;
}

static wired_moqtrun_peer* moqtrun_find_by_wt(
    wired_moqt_hub* hub, wired_wt_session* s) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (moqtrun_peer_matches_wt(&hub->peers[i], s)) return &hub->peers[i];
  return 0;
}

static wired_moqtrun_peer* moqtrun_alloc(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (!hub->peers[i].in_use) return &hub->peers[i];
  return 0;
}

/* Forward-declared: defined below (moqtrun_track_claim's own doc), reused
 * here so a never-yet-claimed track's relays[] is meaningful (0, not
 * garbage) the first time anything reads it -- including this hub's own
 * stale-relay walk on that track's first-ever claim. Production relies on
 * this hub living in BSS (wired_server.c's g_hub), zeroed by the OS
 * loader; this makes that assumption explicit and correct for ANY
 * allocation (BSS, heap, or a test's stack local) instead of leaving it
 * implicit. */
static void moqtrun_track_clear_relays(wired_moqtrun_track* t);

static void moqtrun_peer_clear_relays(wired_moqtrun_peer* p) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    moqtrun_track_clear_relays(&p->tracks[t]);
}

void wired_moqt_init(wired_moqt_hub* hub, wired_moqt_io io) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    hub->peers[i].in_use = 0;
    moqtrun_peer_clear_relays(&hub->peers[i]);
  }
  moqtrun_track_clear_relays(&hub->blob_track);
  moqtrun_track_clear_relays(&hub->live.track);
  hub->io                   = io;
  hub->authorize_subscribe  = 0;
  hub->authorize_ctx        = 0;
  hub->stat_frag_drop       = 0;
  hub->stat_relay_sent      = 0;
  hub->stat_relay_drop      = 0;
  hub->stat_open_drop       = 0;
  hub->stat_relay_reset     = 0;
  hub->stat_relay_full      = 0;
  hub->stat_dg_sent         = 0;
  hub->stat_dg_drop         = 0;
  hub->stat_dg_bad          = 0;
  hub->blob_track.in_use    = 0;
  hub->live.track.in_use    = 0;
  hub->live.last_now_ms     = 0;
  hub->stat_live_sent       = 0;
  hub->stat_live_drop       = 0;
  hub->reliable_alias_limit = 0;
  hub->stat_rel_stall       = 0;
  hub->stat_rel_overflow    = 0;
  for (usz i = 0; i < WIRED_MOQTREL_POOL; i++) moqtrel_reset(&hub->rel_pool[i]);
}

/* SS10 common envelope (Type vi64 + 16-bit Length + Body): every control
 * message this hub sends goes through this one encoder, so the Length
 * backpatch lives in exactly one place. Returns bytes written, or 0 if the
 * body encoder failed (buf too small). */
typedef int (*moqtrun_body_encode_fn)(wired_mspan, usz*, const void*);

static usz moqtrun_envelope_put(
    wired_mspan            buf,
    u64                    type,
    moqtrun_body_encode_fn body_fn,
    const void*            msg) {
  usz eoff = 0;
  if (!moqvi_put(buf, &eoff, type)) return 0;
  usz len_at = eoff;
  eoff += 2;
  usz body_at = eoff;
  if (!body_fn(buf, &eoff, msg)) return 0;
  buf.p[len_at]     = (u8)((eoff - body_at) >> 8);
  buf.p[len_at + 1] = (u8)(eoff - body_at);
  return eoff;
}

static int moqtrun_encode_setup(wired_mspan buf, usz* off, const void* m) {
  return moqctl_setup_encode(buf, off, m);
}

/* draft 3.3: the control stream's first message is the endpoint's own
 * SETUP, no Setup Options (this subset negotiates nothing on the wire).
 * io->open_bidi_stream is responsible for prefixing the WebTransport
 * stream signal (draft-ietf-webtrans-http3-15 4.2) ahead of these bytes --
 * this layer stays session-opaque (wired_wt_session is never dereferenced
 * here, only passed through) so it stays testable without the QUIC/TLS
 * stack; see moqtrun.h's io table doc. */
static u64 moqtrun_send_setup(wired_moqt_io* io, wired_wt_session* s, u8* buf) {
  moqctl_setup setup = {0};
  usz          n     = moqtrun_envelope_put(
      wired_mspan_of(buf, WIRED_MOQTRUN_CTL_SEND_BUF), MOQCTL_T_SETUP,
      moqtrun_encode_setup, &setup);
  i64 sid = io->open_bidi_stream(s, wired_span_of(buf, n));
  return sid < 0 ? 0 : (u64)sid;
}

/* Initializes a freshly allocated peer slot for s and sends its SETUP,
 * split out of wired_moqt_on_session to keep that function's own branch
 * count at the CCN gate. SETUP goes out on send_bufs[0]: that slot becomes
 * "armed" (open_bidi_stream holds the same view/ACK contract as
 * stream_send, per srvrun.h), so armed_idx starts at 0 and every reply
 * queued afterward goes to the OTHER slot (moqtrun_queue_reply's doc). */
static void moqtrun_init_peer(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_wt_session* s) {
  p->in_use          = 1;
  p->wt              = s;
  p->request_id_next = 1; /* hub is the server: odd, 1-origin (draft SS10.2) */
  p->sub_names_n     = 0;
  p->sub_names_at    = 0;
  p->send_lens[0]    = 0;
  p->send_lens[1]    = 0;
  p->armed_idx       = 0;
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    p->tracks[t].in_use = 0;
  moqsess_init(&p->sess);
  p->control_stream_id = moqtrun_send_setup(&hub->io, s, p->send_bufs[0]);
  moqsess_step(&p->sess, MOQSESS_EV_SENT_SETUP);
}

void wired_moqt_on_session(
    void* app_ctx, wired_wt_session* s, wired_span path, wired_span protocol) {
  (void)path;
  (void)protocol;
  wired_moqt_hub* hub = (wired_moqt_hub*)app_ctx;
  /* srvrun's wt_on_session doc promises "fires once after [the 2xx] is
   * built", but a duplicate Extended CONNECT can still reach the app layer
   * (e.g. a retried/speculative one) -- draft 3.3 permits only one control
   * stream per peer per session, so a second SETUP here would itself be the
   * protocol violation this hub is supposed to prevent, not just redundant
   * work. Guard by session identity: a callback for an already-tracked s is
   * a no-op instead of allocating a second peer slot and sending SETUP
   * twice on the same WT session. */
  if (moqtrun_find_by_wt(hub, s)) return;
  wired_moqtrun_peer* p = moqtrun_alloc(hub);
  if (!p) return;
  moqtrun_init_peer(hub, p, s);
}

/* ===================== control-message handlers ===================== */

/* draft SS10.2 Message Parameter types this hub refuses to accept/send
 * (loss-free-hub timeout defense). */
static int moqtrun_is_timeout_type(u64 t) {
  return t == MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT ||
         t == MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT;
}

static int moqtrun_param_is_nonzero_timeout(const moqctl_param* item) {
  return moqtrun_is_timeout_type(item->type) && item->vi != 0;
}

static int moqtrun_has_timeout_param(const moqctl_params* params) {
  for (usz i = 0; i < params->n; i++)
    if (moqtrun_param_is_nonzero_timeout(&params->items[i])) return 1;
  return 0;
}

/* Appends one control message's already-encoded bytes to p's per-dispatch
 * reply queue -- moqtrun.h's send_bufs/armed_idx doc explains why this is
 * the OTHER slot from p->armed_idx, never the armed one: every handler
 * queues here instead of calling stream_send itself, so a dispatch with
 * several replies (e.g. one SUBSCRIBE per other peer) still calls
 * stream_send only once. Silently drops on overflow
 * (WIRED_MOQTRUN_CTL_SEND_BUF is sized for the worst case this hub's own
 * protocol subset can produce, so overflow never happens in practice). */
static void moqtrun_queue_reply(wired_moqtrun_peer* p, wired_span msg) {
  int pending_idx = p->armed_idx ^ 1;
  if (p->send_lens[pending_idx] + msg.n > WIRED_MOQTRUN_CTL_SEND_BUF) return;
  bytes_memcpy(
      p->send_bufs[pending_idx] + p->send_lens[pending_idx], msg.p, msg.n);
  p->send_lens[pending_idx] += msg.n;
}

/* Sends every reply queued in p's pending slot, in one stream_send call.
 * Called at both the START and the END of moqtrun_dispatch_ctl_stream (see
 * its own doc for why one call is not enough): a queue can still hold an
 * earlier dispatch's replies when this one begins, because
 * wired_server_wt_stream_send refuses a new round on a keep-open bidi
 * stream until the PREVIOUS round is fully acknowledged (srvrun.c's
 * srvrun_wtsend_appendable) -- an ACK needs at least one more event-loop
 * step than a single app callback ever gets, so two control messages
 * arriving in back-to-back dispatches (e.g. PUBLISH then SUBSCRIBE) can
 * easily straddle that boundary.
 *
 * On success, armed_idx swaps to the slot that was just handed to
 * stream_send (moqtrun.h's own doc on why that slot's bytes must not be
 * touched again until ACKed) -- and appendable() only returns true once
 * the PREVIOUS armed round is fully ACKed, so success here also proves the
 * OLD armed slot is now safe to reuse as the next pending target (it is
 * never handed to stream_send again). On failure (still pending) the
 * pending slot is left untouched so the NEXT dispatch's start-of-call
 * flush retries it, growing with that dispatch's own new replies appended
 * after it. A dispatch that queued nothing (send_lens[pending]==0) sends
 * nothing -- wired_server_wt_stream_send never accepts an empty payload. */
static void moqtrun_flush_replies(wired_moqt_io* io, wired_moqtrun_peer* p) {
  int pending_idx = p->armed_idx ^ 1;
  if (p->send_lens[pending_idx] == 0) return;
  int r = io->stream_send(
      p->wt, p->control_stream_id,
      wired_span_of(p->send_bufs[pending_idx], p->send_lens[pending_idx]), 0);
  if (r <= 0) return;
  p->send_lens[p->armed_idx] = 0; /* old armed slot: now safe to reuse */
  p->armed_idx               = pending_idx;
}

static int moqtrun_encode_request_error(
    wired_mspan buf, usz* off, const void* m) {
  return moqctl_request_error_encode(buf, off, m);
}

static void moqtrun_send_request_error(wired_moqtrun_peer* p, u64 code) {
  u8                   msg[WIRED_MOQTRUN_CTL_MSG_MAX];
  moqctl_request_error e = {0};
  e.error_code           = code;
  usz n                  = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_REQUEST_ERROR,
      moqtrun_encode_request_error, &e);
  moqtrun_queue_reply(p, wired_span_of(msg, n));
}

/* Copies name into t->name (Track Name = participant id, or
 * "<participant id>/audio"), truncated to WIRED_MOQTRUN_MAX_NAME (room ids
 * are short; a real deployment would reject an oversized one instead --
 * ponytail: no such input in this subset's usage). */
static void moqtrun_record_track_name(wired_moqtrun_track* t, wired_span name) {
  usz n = name.n < WIRED_MOQTRUN_MAX_NAME ? name.n : WIRED_MOQTRUN_MAX_NAME;
  bytes_memcpy(t->name, name.p, n);
  t->name_len = n;
}

static int moqtrun_bytes_eq(const u8* a, const u8* b, usz n) {
  for (usz i = 0; i < n; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

static int moqtrun_track_name_matches(
    const wired_moqtrun_track* t, wired_span name) {
  return t->in_use && t->name_len == name.n &&
         moqtrun_bytes_eq(t->name, name.p, name.n);
}

/* Finds p's own track slot already PUBLISHed under name, else 0. */
static wired_moqtrun_track* moqtrun_track_slot_for_name(
    wired_moqtrun_peer* p, wired_span name) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    if (moqtrun_track_name_matches(&p->tracks[t], name)) return &p->tracks[t];
  return 0;
}

/* Finds p's first free track slot, else 0 (all
 * WIRED_MOQTRUN_MAX_TRACKS_PER_PEER already in use). */
static wired_moqtrun_track* moqtrun_track_free_slot(wired_moqtrun_peer* p) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    if (!p->tracks[t].in_use) return &p->tracks[t];
  return 0;
}

/* Returns p's slot for a PUBLISH naming name: the existing slot if this
 * name was already PUBLISHed (re-PUBLISH reuses it, matching the prior
 * single-track hub's overwrite behavior), else a fresh free slot, else 0
 * when both slots are already taken by other names. */
static wired_moqtrun_track* moqtrun_track_alloc_slot(
    wired_moqtrun_peer* p, wired_span name) {
  wired_moqtrun_track* existing = moqtrun_track_slot_for_name(p, name);
  return existing ? existing : moqtrun_track_free_slot(p);
}

/* 1 iff sub-name ring entry i of p equals name. */
static int moqtrun_sub_name_eq(
    const wired_moqtrun_peer* p, usz i, wired_span name) {
  return p->sub_name_lens[i] == name.n &&
         moqtrun_bytes_eq(p->sub_names[i], name.p, name.n);
}

/* 1 iff p has recorded a successful SUBSCRIBE for name. */
static int moqtrun_sub_name_known(
    const wired_moqtrun_peer* p, wired_span name) {
  for (usz i = 0; i < p->sub_names_n; i++)
    if (moqtrun_sub_name_eq(p, i, name)) return 1;
  return 0;
}

static void moqtrun_sub_name_store(wired_moqtrun_peer* p, wired_span name) {
  bytes_memcpy(p->sub_names[p->sub_names_at], name.p, name.n);
  p->sub_name_lens[p->sub_names_at] = name.n;
  p->sub_names_at = (u8)((p->sub_names_at + 1) % WIRED_MOQTRUN_SUB_NAMES);
  if (p->sub_names_n < WIRED_MOQTRUN_SUB_NAMES) p->sub_names_n++;
}

/* Remember a name p subscribed to, so a later REPUBLISH of it can
 * re-attach p (wired_moqtrun_peer.sub_names' doc). An oversized name could
 * never match a recorded track name, so it is not stored. */
static void moqtrun_note_sub_name(wired_moqtrun_peer* p, wired_span name) {
  if (name.n > WIRED_MOQTRUN_MAX_NAME) return;
  if (moqtrun_sub_name_known(p, name)) return;
  moqtrun_sub_name_store(p, name);
}

static int moqtrun_encode_request_ok(wired_mspan buf, usz* off, const void* m) {
  return moqctl_request_ok_encode(buf, off, m);
}

/* Clears t's subscriber slots -- only needed the first time a fresh (not
 * re-PUBLISHed) slot is claimed. */
static void moqtrun_track_clear_subs(wired_moqtrun_track* t) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) t->subs[i].active = 0;
}

static void moqtrun_track_clear_relays(wired_moqtrun_track* t) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++) t->relays[r].in_use = 0;
}

/* 1 iff relay r's subscriber slot si names a stream AND that slot's
 * subscription is still Established -- the two preconditions
 * moqtrun_relay_reset_one_sub needs before it may touch hub->peers[] (an
 * inactive slot's session_idx is garbage, not a safe index: freestanding
 * memory starts unzeroed, the same reason every other sub->session_idx use
 * in this file is guarded on ->active first, e.g. moqtrun_relay_object). */
static int moqtrun_relay_orphan_ok(
    const wired_moqtrun_track* t, const wired_moqtrun_relay* r, usz si) {
  return r->sub_stream_set[si] && t->subs[si].active;
}

/* Resets subscriber slot si's still-open relay stream on relay r, if it has
 * one: the WT layer, not just this hub's own bookkeeping, must be told the
 * stream is dead, or the subscriber's peer-granted uni-stream credit for it
 * is never released (moqtrun_track_reset_stale_relays' own doc). */
static void moqtrun_relay_reset_one_sub(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    wired_moqtrun_relay* r,
    usz                  si) {
  if (!moqtrun_relay_orphan_ok(t, r, si)) return;
  wired_moqtrun_peer* dst = &hub->peers[t->subs[si].session_idx];
  if (dst->in_use) hub->io.stream_reset(dst->wt, r->sub_stream_id[si], 0);
  r->sub_stream_set[si] = 0;
}

static void moqtrun_relay_reset_stale(
    wired_moqt_hub* hub, wired_moqtrun_track* t, wired_moqtrun_relay* r) {
  if (!r->in_use) return;
  for (usz si = 0; si < WIRED_MOQTRUN_MAX_SUBS; si++)
    moqtrun_relay_reset_one_sub(hub, t, r, si);
}

/* A publisher that drops mid-share (crash, network loss -- no clean FIN)
 * leaves every subscriber's relay stream open on the transport even though
 * this hub's own bookkeeping forgot it on session_close
 * (moqtrun_relays_clear_sub only clears sub_stream_set, never the
 * underlying stream). Left alone, every drop+reshare cycle permanently
 * burns one uni-stream credit slot on every subscriber (RFC 9000 4.6):
 * stream ids never get reused, and nothing else ever resets one of these
 * orphans, until the subscriber's whole connection eventually has no
 * credit left for ANY new stream, chat included -- observed live as
 * screen shares and chat both going silent for someone who never touched
 * their own browser. Called BEFORE moqtrun_track_clear_relays wipes the
 * bookkeeping this walk needs. */
static void moqtrun_track_reset_stale_relays(
    wired_moqt_hub* hub, wired_moqtrun_track* t) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++)
    moqtrun_relay_reset_stale(hub, t, &t->relays[r]);
}

/* Claims slot t for a PUBLISH naming name/track_alias: clears subs only on
 * a fresh (not-yet-in_use) slot, so a re-PUBLISH under the same name keeps
 * its existing subscribers (matching the prior single-track hub's
 * overwrite behavior). Relays always clear: a (re-)PUBLISH means the
 * publisher's old streams are gone (and freestanding memory starts
 * unzeroed, so a fresh slot's relays hold garbage until this) -- but any
 * of those old streams still open on a subscriber's transport are reset
 * first, not just forgotten (moqtrun_track_reset_stale_relays' own doc). */
static void moqtrun_track_claim(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    wired_span           name,
    u64                  track_alias) {
  /* Reset every orphaned relay stream BEFORE clear_subs deactivates the
   * very subs[] entries this walk reads (moqtrun_track_reset_stale_relays'
   * own doc) -- a fresh claim (in_use was 0, e.g. after a reconnect that
   * re-initialized this peer's whole tracks[]) always clears subs, whether
   * or not the publisher rejoining is who they used to be; the reattach
   * that follows in moqtrun_handle_publish re-derives who to reattach from
   * each SUBSCRIBER's own surviving sub_names ring instead. */
  moqtrun_track_reset_stale_relays(hub, t);
  if (!t->in_use) moqtrun_track_clear_subs(t);
  t->in_use    = 1;
  t->own_alias = track_alias;
  moqtrun_track_clear_relays(t);
  moqtrun_record_track_name(t, name);
}

static void moqtrun_reattach_subs(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    usz                  pub_idx,
    wired_span           name);

/* draft SS10.9 PUBLISH: accept a track into a free (or matching-name) slot
 * and reply REQUEST_OK; a third distinct track name (no free slot) gets
 * REQUEST_ERROR instead of silently overwriting an existing track. */
static void moqtrun_handle_publish(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  usz            off = 0;
  moqctl_publish m;
  if (moqctl_publish_take(body, &off, &m) != MOQCTL_OK) return;
  wired_moqtrun_track* t = moqtrun_track_alloc_slot(p, m.name.name);
  if (!t) {
    moqtrun_send_request_error(p, MOQCTL_ERR_NOT_SUPPORTED);
    return;
  }
  moqtrun_track_claim(hub, t, m.name.name, m.track_alias);
  moqtrun_reattach_subs(hub, t, peer_idx, m.name.name);
  u8                msg[WIRED_MOQTRUN_CTL_MSG_MAX];
  moqctl_request_ok ok = {0};
  usz               n  = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_REQUEST_OK,
      moqtrun_encode_request_ok, &ok);
  moqtrun_queue_reply(p, wired_span_of(msg, n));
}

/* p's matching track slot if p is a connected peer, else 0 -- guards the
 * in_use check ahead of the name scan so the caller's loop body is one
 * unconditional call. */
static wired_moqtrun_track* moqtrun_peer_track_for_name(
    wired_moqtrun_peer* p, wired_span name) {
  return p->in_use ? moqtrun_track_slot_for_name(p, name) : 0;
}

/* Finds the track whose own PUBLISHed Track Name equals the requested
 * SUBSCRIBE's Track Name (room membership keys on participant id/suffix,
 * namespace is hub-fixed and not compared), across every connected peer. */
static wired_moqtrun_track* moqtrun_find_published_track(
    wired_moqt_hub* hub, const moqctl_ftn* name) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    wired_moqtrun_track* t =
        moqtrun_peer_track_for_name(&hub->peers[i], name->name);
    if (t) return t;
  }
  return 0;
}

static wired_moqtrun_sub* moqtrun_sub_slot(wired_moqtrun_track* track) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (!track->subs[i].active) return &track->subs[i];
  return 0;
}

static u64 moqtrun_alias_floor(const wired_moqtrun_track* track, usz i) {
  return track->subs[i].active ? track->subs[i].track_alias + 1 : 0;
}

static u64 moqtrun_next_alias(const wired_moqtrun_track* track) {
  u64 max_seen = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    u64 floor = moqtrun_alias_floor(track, i);
    if (floor > max_seen) max_seen = floor;
  }
  return max_seen;
}

/* 1 if sub is an Established subscription held by peer index idx. */
static int moqtrun_sub_is_peer(const wired_moqtrun_sub* sub, usz idx) {
  return sub->active && sub->session_idx == idx;
}

/* The Established sub slot peer index idx holds on t, else 0. */
static wired_moqtrun_sub* moqtrun_track_sub_of_peer(
    wired_moqtrun_track* t, usz idx) {
  for (usz s = 0; s < WIRED_MOQTRUN_MAX_SUBS; s++)
    if (moqtrun_sub_is_peer(&t->subs[s], idx)) return &t->subs[s];
  return 0;
}

/* 1 iff peer i is a live peer OTHER than the publisher. */
static int moqtrun_reattach_peer_live(
    const wired_moqt_hub* hub, usz i, usz pub_idx) {
  return i != pub_idx && hub->peers[i].in_use;
}

/* Re-attach eligibility: a live, different peer, not already subscribed on
 * this track, that recorded a SUBSCRIBE for this name. */
static int moqtrun_reattach_wanted(
    const wired_moqt_hub* hub,
    wired_moqtrun_track*  t,
    usz                   i,
    usz                   pub_idx,
    wired_span            name) {
  if (!moqtrun_reattach_peer_live(hub, i, pub_idx)) return 0;
  if (moqtrun_track_sub_of_peer(t, i)) return 0;
  return moqtrun_sub_name_known(&hub->peers[i], name);
}

static void moqtrun_reattach_one_sub(wired_moqtrun_track* track, usz i) {
  wired_moqtrun_sub* slot = moqtrun_sub_slot(track);
  if (!slot) return;
  slot->session_idx = i;
  slot->track_alias = moqtrun_next_alias(track);
  slot->active      = 1;
}

/* A (re)PUBLISHed name re-attaches every still-connected peer that had
 * subscribed to it before -- silently, with no SUBSCRIBE_OK: the
 * subscriber's client still believes its original subscription stands
 * (that belief, standing while the hub-side subscription had died with
 * the publisher's previous incarnation, is exactly the played-into-
 * silence bug this repairs). The relayed bytes carry the publisher's own
 * SUBGROUP_HEADER alias, which the client maps statically, so no
 * client-visible state needs renegotiating. */
static void moqtrun_reattach_subs(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    usz                  pub_idx,
    wired_span           name) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (moqtrun_reattach_wanted(hub, track, i, pub_idx, name))
      moqtrun_reattach_one_sub(track, i);
}

static int moqtrun_encode_subscribe_ok(
    wired_mspan buf, usz* off, const void* m) {
  return moqctl_subscribe_ok_encode(buf, off, m);
}

static void moqtrun_queue_subscribe_ok(wired_moqtrun_peer* p, u64 alias) {
  u8                  msg[WIRED_MOQTRUN_CTL_MSG_MAX];
  moqctl_subscribe_ok ok = {0};
  ok.track_alias         = alias;
  usz n                  = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_SUBSCRIBE_OK,
      moqtrun_encode_subscribe_ok, &ok);
  moqtrun_queue_reply(p, wired_span_of(msg, n));
}

/* Records slot (peer_idx, a fresh alias) against track and replies
 * SUBSCRIBE_OK with that alias. */
static void moqtrun_accept_subscribe(
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* track,
    wired_moqtrun_sub*   slot,
    usz                  peer_idx) {
  slot->session_idx = peer_idx;
  slot->track_alias = moqtrun_next_alias(track);
  slot->active      = 1;
  moqtrun_queue_subscribe_ok(p, slot->track_alias);
}

/* A peer's first SUBSCRIBE for the hub's blob: one io.send_uni with the
 * whole framed bytes, and only an accepted send records the subscription
 * (a refused one answers REQUEST_ERROR, so the peer's next SUBSCRIBE tries
 * again). Unlike a peer track's per-subscriber alias, SUBSCRIBE_OK carries
 * the blob's own alias -- the one its framed header has -- so the
 * subscriber can bind the stream to this subscription. */
static void moqtrun_blob_send_first(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx) {
  wired_moqtrun_sub* slot = moqtrun_sub_slot(&hub->blob_track);
  if (!slot) {
    moqtrun_send_request_error(p, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  if (hub->io.send_uni(p->wt, hub->blob_wire) < 0) {
    hub->stat_open_drop++;
    moqtrun_send_request_error(p, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  slot->session_idx = peer_idx;
  slot->track_alias = hub->blob_track.own_alias;
  slot->active      = 1;
  moqtrun_queue_subscribe_ok(p, slot->track_alias);
}

/* SUBSCRIBE for the hub's own blob track: a peer already holding a
 * subscription is answered SUBSCRIBE_OK again (its copy is on the way or
 * delivered -- never sent twice), anyone else gets the blob now. */
static void moqtrun_subscribe_blob(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx) {
  wired_moqtrun_sub* held =
      moqtrun_track_sub_of_peer(&hub->blob_track, peer_idx);
  if (held) {
    moqtrun_queue_subscribe_ok(p, held->track_alias);
    return;
  }
  moqtrun_blob_send_first(hub, p, peer_idx);
}

/* SUBSCRIBE on a found peer track: a peer already holding a subscription
 * is answered SUBSCRIBE_OK again with the alias it holds (the client
 * resends SUBSCRIBE until a chunk arrives, and an idle track never sends
 * one -- each resend must not consume another slot), anyone else gets a
 * fresh slot, or DOES_NOT_EXIST once the table is full. */
static void moqtrun_subscribe_peer_track(
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* track,
    usz                  peer_idx,
    wired_span           name) {
  wired_moqtrun_sub* held = moqtrun_track_sub_of_peer(track, peer_idx);
  if (held) {
    moqtrun_queue_subscribe_ok(p, held->track_alias);
    return;
  }
  wired_moqtrun_sub* slot = moqtrun_sub_slot(track);
  if (!slot) {
    moqtrun_send_request_error(p, MOQCTL_ERR_DOES_NOT_EXIST);
    return;
  }
  moqtrun_accept_subscribe(p, track, slot, peer_idx);
  moqtrun_note_sub_name(p, name);
}

/* draft SS10.6 SUBSCRIBE for a peer-published track: find it and reply
 * SUBSCRIBE_OK with an assigned Track Alias, else DOES_NOT_EXIST. */
static void moqtrun_route_peer_subscribe(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m) {
  wired_moqtrun_track* track = moqtrun_find_published_track(hub, &m->name);
  if (!track) {
    moqtrun_send_request_error(p, MOQCTL_ERR_DOES_NOT_EXIST);
    return;
  }
  moqtrun_subscribe_peer_track(p, track, peer_idx, m->name.name);
}

static void moqtrun_subscribe_live(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx);

/* draft SS10.6 SUBSCRIBE: the hub's own tracks answer first (they win
 * over a peer track of the same name), everything else is matched against
 * the peers' PUBLISHed tracks. Caller has already rejected timeout
 * parameters. */
static void moqtrun_route_subscribe(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m) {
  if (moqtrun_track_name_matches(&hub->blob_track, m->name.name)) {
    moqtrun_subscribe_blob(hub, p, peer_idx);
    return;
  }
  if (moqtrun_track_name_matches(&hub->live.track, m->name.name)) {
    moqtrun_subscribe_live(hub, p, peer_idx);
    return;
  }
  moqtrun_route_peer_subscribe(hub, p, peer_idx, m);
}

/* First AUTHORIZATION TOKEN parameter (draft SS10.2.2) of a message, or
 * 0 when it carries none. */
static const moqctl_token* moqtrun_auth_token_of(const moqctl_params* params) {
  for (usz i = 0; i < params->n; i++)
    if (params->items[i].type == MOQCTL_PARAM_AUTHORIZATION_TOKEN)
      return &params->items[i].token;
  return 0;
}

/* This hub never advertises MAX_AUTH_TOKEN_CACHE_SIZE (SS10.3.1.3), so its
 * token cache is 0 bytes and Token Aliases are prohibited: only USE_VALUE
 * can be honoured. ponytail: a REGISTER should terminate the session with
 * AUTH_TOKEN_CACHE_OVERFLOW (SS10.2.2) -- the hub has no session-close io,
 * so it refuses the request instead; add an io.close when one exists. */
static int moqtrun_token_uses_alias(const moqctl_token* t) {
  return t && t->alias_type != MOQCTL_TOKEN_USE_VALUE;
}

/* draft SS13.3: "Relays will verify the token to ensure that the request
 * is authorized." Every SUBSCRIBE passes here before any track matching
 * (own blob/live tracks and peer tracks alike). 1 + *code when refused. */
static int moqtrun_subscribe_refused(
    const wired_moqt_hub* hub, const moqctl_subscribe* m, u64* code) {
  const moqctl_token* t = moqtrun_auth_token_of(&m->params);
  *code                 = MOQCTL_ERR_MALFORMED_AUTH_TOKEN;
  if (moqtrun_token_uses_alias(t)) return 1;
  *code = MOQCTL_ERR_UNAUTHORIZED;
  if (!hub->authorize_subscribe) return 0;
  return !hub->authorize_subscribe(hub->authorize_ctx, &m->name, t);
}

/* draft SS10.6 SUBSCRIBE: reject non-zero delivery-timeout parameters and
 * unauthorized subscribers, else delegate matching + response to
 * moqtrun_route_subscribe. */
static void moqtrun_subscribe_checked(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m) {
  u64 code;
  if (moqtrun_has_timeout_param(&m->params)) {
    moqtrun_send_request_error(p, MOQCTL_ERR_NOT_SUPPORTED);
    return;
  }
  if (moqtrun_subscribe_refused(hub, m, &code)) {
    moqtrun_send_request_error(p, code);
    return;
  }
  moqtrun_route_subscribe(hub, p, peer_idx, m);
}

static void moqtrun_handle_subscribe(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  usz              off = 0;
  moqctl_subscribe m;
  if (moqctl_subscribe_take(body, &off, &m) != MOQCTL_OK) return;
  moqtrun_subscribe_checked(hub, p, peer_idx, &m);
}

static void moqtrun_handle_not_supported(wired_moqtrun_peer* p) {
  moqtrun_send_request_error(p, MOQCTL_ERR_NOT_SUPPORTED);
}

/* draft 5.1: a GOAWAY arriving on a request stream (not the control
 * stream) is informational in this subset -- accepted without closing the
 * session. The 2nd-GOAWAY-on-one-stream violation is a sess-layer
 * concern the caller already routes through moqsess_step; nothing
 * further to do here since this hub sends no GOAWAY of its own on a
 * request stream. */
static void moqtrun_handle_request_goaway(void) {}

typedef void (*moqtrun_ctl_fn)(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);

static void moqtrun_dispatch_publish(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  moqtrun_handle_publish(hub, p, peer_idx, body);
}

static void moqtrun_dispatch_subscribe(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  moqtrun_handle_subscribe(hub, p, peer_idx, body);
}

static void moqtrun_dispatch_not_supported(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)hub;
  (void)peer_idx;
  (void)body;
  moqtrun_handle_not_supported(p);
}

static void moqtrun_dispatch_goaway(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)hub;
  (void)p;
  (void)peer_idx;
  (void)body;
  moqtrun_handle_request_goaway();
}

/* First-type table (draft table in ctl.h's peek_type doc): only PUBLISH and
 * SUBSCRIBE are implemented; every other First type this hub can see on a
 * fresh request stream gets NOT_SUPPORTED. GOAWAY is not a
 * First type but may legally appear mid-stream, so it is routed
 * the same table for request-stream dispatch below. */
static const struct {
  u64            type;
  moqtrun_ctl_fn fn;
} moqtrun_ctl_table[] = {
    {MOQCTL_T_PUBLISH, moqtrun_dispatch_publish},
    {MOQCTL_T_SUBSCRIBE, moqtrun_dispatch_subscribe},
    {MOQCTL_T_GOAWAY, moqtrun_dispatch_goaway},
};
#define MOQTRUN_CTL_TABLE_N \
  (sizeof(moqtrun_ctl_table) / sizeof(moqtrun_ctl_table[0]))

static moqtrun_ctl_fn moqtrun_ctl_lookup(u64 type) {
  for (usz i = 0; i < MOQTRUN_CTL_TABLE_N; i++)
    if (moqtrun_ctl_table[i].type == type) return moqtrun_ctl_table[i].fn;
  return moqtrun_dispatch_not_supported;
}

/* Dispatches every complete control message found in data (a request
 * stream carries exactly one; the shared control stream may carry more
 * than one per call). peer_idx is passed through for handlers that need
 * to record which session a subscription belongs to. Every handler queues
 * its reply (moqtrun_queue_reply) rather than sending it immediately.
 *
 * Flushes at BOTH ends: the leading flush retries whatever an earlier
 * dispatch could not send yet (moqtrun_flush_replies' own doc -- a
 * keep-open bidi stream's previous round must be acknowledged before a new
 * one is accepted, and that can still be pending when the next dispatch
 * starts), and the trailing flush sends this dispatch's own new replies.
 * Two calls, never more, keeps every reply either delivered or still
 * queued for the next try -- never dropped. */
static void moqtrun_dispatch_ctl_stream(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span data) {
  usz off = 0;
  moqtrun_flush_replies(&hub->io, p);
  while (off < data.n) {
    u64        type = 0;
    wired_span body = {0, 0};
    int        r    = moqctl_peek_type(data, &off, &type, &body);
    if (r != MOQCTL_OK) break;
    moqtrun_ctl_lookup(type)(hub, p, peer_idx, body);
  }
  moqtrun_flush_replies(&hub->io, p);
}

/* ===================== hub-owned blob track ===================== */

usz wired_moqt_publish_blob(
    wired_moqt_hub* hub,
    wired_span      name,
    u64             track_alias,
    wired_span      blob,
    wired_mspan     wire) {
  usz n = moqdata_blob_build(wire, track_alias, blob);
  if (n == 0) return 0;
  moqtrun_track_claim(hub, &hub->blob_track, name, track_alias);
  hub->blob_wire = wired_span_of(wire.p, n);
  return n;
}

/* ===================== hub-owned live track ===================== */

/* 1 iff any fragment is empty: an empty Object payload requires an
 * explicit Status varint after Payload Length 0 (moqdata_obj_put's doc),
 * which the live head (Delta + Length only) never carries -- such a
 * fragment could not frame as a valid Object, so the publish is refused
 * whole. */
static int moqtrun_live_has_empty_frag(const wired_span* frags, usz n_frags) {
  for (usz f = 0; f < n_frags; f++)
    if (frags[f].n == 0) return 1;
  return 0;
}

static int moqtrun_live_args_bad(
    const wired_span* frags, usz n_frags, u64 group_ms) {
  if (n_frags == 0 || group_ms == 0) return 1;
  return moqtrun_live_has_empty_frag(frags, n_frags);
}

int wired_moqt_publish_live(
    wired_moqt_hub*   hub,
    wired_span        name,
    u64               track_alias,
    const wired_span* frags,
    usz               n_frags,
    u64               group_ms,
    u64               now_ms) {
  if (moqtrun_live_args_bad(frags, n_frags, group_ms)) return 0;
  hub->live.track.in_use = 0; /* a re-publish forgets old subscribers */
  moqtrun_track_claim(hub, &hub->live.track, name, track_alias);
  hub->live.frags       = frags;
  hub->live.n_frags     = n_frags;
  hub->live.t0_ms       = now_ms;
  hub->live.group_ms    = group_ms;
  hub->live.last_now_ms = now_ms;
  return 1;
}

static u64 moqtrun_live_group_at(const wired_moqtrun_live* live, u64 now_ms) {
  return now_ms < live->t0_ms ? 0 : (now_ms - live->t0_ms) / live->group_ms;
}

/* The Object's ID Delta 0 and Payload Length -- exactly the varints
 * moqdata_obj_put emits ahead of a non-empty payload, so head||fragment
 * is byte-identical to what moqdata_obj_put would have written. */
static int moqtrun_live_head_obj(wired_mspan buf, usz* off, usz frag_len) {
  if (!moqvi_put(buf, off, 0)) return 0;
  return moqvi_put(buf, off, frag_len);
}

/* SUBGROUP_HEADER (Type 0x70 shape, live alias, Group g) + the Object's
 * ID Delta 0 and Payload Length -- the framing that precedes the fragment
 * bytes on the wire. Returns the head length (<= MOQDATA_MSG_OVERHEAD). */
static usz moqtrun_live_head(
    const wired_moqtrun_live* live, u64 group, usz frag_len, u8* head) {
  usz            off = 0;
  moqdata_subhdr h   = {0};
  h.type             = 0x70;
  h.track_alias      = live->track.own_alias;
  h.group_id         = group;
  wired_mspan buf    = wired_mspan_of(head, MOQDATA_MSG_OVERHEAD);
  if (moqdata_subhdr_put(buf, &off, &h) != MOQDATA_OK) return 0;
  if (!moqtrun_live_head_obj(buf, &off, frag_len)) return 0;
  return off;
}

/* 1 iff sub slot i still owes Group g (never sent, or last sent older). */
static int moqtrun_live_owes(const wired_moqtrun_live* live, usz i, u64 g) {
  return !live->sent_any[i] || live->sent_group[i] < g;
}

/* Groups the clock skipped past sub slot i's last accepted send (0 when
 * none): each is a fragment this subscriber was never sent -- never sent
 * late once its Group has passed, only counted. */
static u64 moqtrun_live_gap(const wired_moqtrun_live* live, usz i, u64 g) {
  return live->sent_any[i] && live->sent_group[i] + 1 < g
             ? g - live->sent_group[i] - 1
             : 0;
}

/* Sends Group g to sub slot i; on acceptance counts any skipped Groups
 * and records g. A refused send records nothing (retried next tick while
 * the clock is still in g). */
static void moqtrun_live_send_one(wired_moqt_hub* hub, usz i, u64 g) {
  wired_moqtrun_live* live = &hub->live;
  wired_moqtrun_peer* dst  = &hub->peers[live->track.subs[i].session_idx];
  wired_span          frag = live->frags[g % live->n_frags];
  u8                  head[MOQDATA_MSG_OVERHEAD];
  usz                 hn = moqtrun_live_head(live, g, frag.n, head);
  if (!dst->in_use) return;
  if (hub->io.send_uni2(dst->wt, wired_span_of(head, hn), frag) < 0) return;
  hub->stat_live_drop += moqtrun_live_gap(live, i, g);
  live->sent_group[i] = g;
  live->sent_any[i]   = 1;
  hub->stat_live_sent++;
}

static void moqtrun_live_serve_sub(wired_moqt_hub* hub, usz i, u64 g) {
  if (!hub->live.track.subs[i].active) return;
  if (!moqtrun_live_owes(&hub->live, i, g)) return;
  moqtrun_live_send_one(hub, i, g);
}

/* Forward-declared: defined in the reliable-relay block below (which sits
 * with the rest of the relay logic); the tick must drive it so refused
 * rounds retry on the clock, not only when the publisher delivers. */
static void moqtrun_rel_tick_all(wired_moqt_hub* hub, u64 now_ms);

void wired_moqt_tick(wired_moqt_hub* hub, u64 now_ms) {
  hub->live.last_now_ms = now_ms;
  moqtrun_rel_tick_all(hub, now_ms);
  if (!hub->live.track.in_use) return;
  u64 g = moqtrun_live_group_at(&hub->live, now_ms);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    moqtrun_live_serve_sub(hub, i, g);
}

/* Records slot for peer_idx, replies SUBSCRIBE_OK with the live track's
 * own alias, and sends the Group current at the last tick at once (its
 * fragment starts with a keyframe). */
static void moqtrun_live_attach(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_sub*  slot,
    usz                 peer_idx) {
  usz i                 = (usz)(slot - hub->live.track.subs);
  slot->session_idx     = peer_idx;
  slot->track_alias     = hub->live.track.own_alias;
  slot->active          = 1;
  hub->live.sent_any[i] = 0;
  moqtrun_queue_subscribe_ok(p, slot->track_alias);
  moqtrun_live_send_one(
      hub, i, moqtrun_live_group_at(&hub->live, hub->live.last_now_ms));
}

/* SUBSCRIBE for the live track: a peer already holding a subscription is
 * answered SUBSCRIBE_OK again (nothing re-sent), anyone else is attached
 * and served the current Group. */
static void moqtrun_subscribe_live(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx) {
  wired_moqtrun_track* t    = &hub->live.track;
  wired_moqtrun_sub*   held = moqtrun_track_sub_of_peer(t, peer_idx);
  if (held) {
    moqtrun_queue_subscribe_ok(p, held->track_alias);
    return;
  }
  wired_moqtrun_sub* slot = moqtrun_sub_slot(t);
  if (!slot) {
    moqtrun_send_request_error(p, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  moqtrun_live_attach(hub, p, slot, peer_idx);
}

/* ===================== data-stream (Object) relay ===================== */

/* One-shot relay of wire to one subscriber: a fresh uni stream, sent and
 * FIN'd in a single io.send_uni call -- the whole-message-in-one-call path
 * (a publisher stream whose data AND fin arrived together). */
static void moqtrun_relay_to_one(
    wired_moqt_hub* hub, const wired_moqtrun_sub* sub, wired_span wire) {
  wired_moqtrun_peer* dst = &hub->peers[sub->session_idx];
  if (!dst->in_use) return;
  /* A refused one-shot open loses this subscriber's whole message (chat's
   * 1 stream = 1 message); count it like the keep-open path's open
   * failures -- stat_open_drop's own doc always promised this loss is
   * never silent, but this call site used to discard the return. */
  if (hub->io.send_uni(dst->wt, wire) < 0) hub->stat_open_drop++;
}

static void moqtrun_relay_object(
    wired_moqt_hub* hub, wired_moqtrun_track* track, wired_span wire) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (track->subs[i].active) moqtrun_relay_to_one(hub, &track->subs[i], wire);
}

/* --- relay map: one entry per in-flight publisher stream (moqtrun.h's
 * wired_moqtrun_relay doc -- keyed by the PUBLISHER's stream id so several
 * of one track's streams can be forwarded concurrently). --- */

static usz moqtrun_decode_object_loop(
    wired_span data, usz* off, const moqdata_subhdr* hdr);

static int moqtrun_relay_matches(
    const wired_moqtrun_relay* r, u64 pub_stream_id) {
  return r->in_use && r->pub_stream_id == pub_stream_id;
}

static wired_moqtrun_relay* moqtrun_track_relay_by_stream(
    wired_moqtrun_track* track, u64 pub_stream_id) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++)
    if (moqtrun_relay_matches(&track->relays[r], pub_stream_id))
      return &track->relays[r];
  return 0;
}

static wired_moqtrun_relay* moqtrun_track_relay_or_null(
    wired_moqtrun_track* track, u64 pub_stream_id) {
  return track->in_use ? moqtrun_track_relay_by_stream(track, pub_stream_id)
                       : 0;
}

/* Finds the relay entry (across p's tracks) already following
 * pub_stream_id, filling *track_out with its owning track. 0 when this
 * stream id is not being relayed (a fresh stream, or one whose relay was
 * dropped). */
static wired_moqtrun_relay* moqtrun_peer_relay_by_stream(
    wired_moqtrun_peer* p, u64 pub_stream_id, wired_moqtrun_track** track_out) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++) {
    wired_moqtrun_relay* r =
        moqtrun_track_relay_or_null(&p->tracks[t], pub_stream_id);
    if (r) {
      *track_out = &p->tracks[t];
      return r;
    }
  }
  return 0;
}

static wired_moqtrun_relay* moqtrun_relay_alloc(wired_moqtrun_track* track) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++)
    if (!track->relays[r].in_use) return &track->relays[r];
  return 0;
}

/* True when this round carries the publisher's own stream FIN with no new
 * Object bytes of its own -- a WebTransport writer's close() can arrive as
 * its own byte-less call, separate from the data written just before it
 * (confirmed against a real browser: a chat message's data and its FIN
 * landed as two distinct wired_moqt_on_stream_data calls). stream_send
 * cannot carry this (srvrun.h: a round's payload must be non-empty), so
 * the caller routes it to stream_fin instead. */
static int moqtrun_is_bare_fin(wired_span wire, int fin) {
  return wire.n == 0 && fin;
}

/* Sub slot i's busy streak has reached the shed threshold: abandon its
 * relay stream (io.stream_reset -- error code 0, MOQT draft-19 defines no
 * standard code for a mid-subgroup abort) so the NEXT round re-opens a
 * fresh stream at the newest frame via moqtrun_relay_late_open, using the
 * relay's saved SUBGROUP_HEADER. A refused reset (the SDK's reset latch is
 * full this step) keeps everything as-is: the saturated streak retries the
 * shed on the next busy round. */
static void moqtrun_relay_shed_one(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    usz                  i) {
  if (relay->sub_busy_streak[i] < WIRED_MOQTRUN_RESET_AFTER_BUSY) return;
  if (hub->io.stream_reset(wt, relay->sub_stream_id[i], 0) != 1) return;
  relay->sub_stream_set[i]  = 0;
  relay->sub_busy_streak[i] = 0;
  hub->stat_relay_reset++;
}

/* One refused relay round for sub slot i: count the drop, advance the busy
 * streak (saturating -- 255 stays 255 so a long starvation cannot wrap back
 * under the threshold), and shed the stream once the streak says the
 * fullness is sustained, not a transient burst. */
static void moqtrun_relay_note_busy(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    usz                  i) {
  hub->stat_relay_drop++;
  if (relay->sub_busy_streak[i] < 255) relay->sub_busy_streak[i]++;
  moqtrun_relay_shed_one(hub, wt, relay, i);
}

/* Forwards one round of publisher bytes to sub slot i's already-open relay
 * stream: a bare FIN closes it via stream_fin (moqtrun_is_bare_fin's doc),
 * anything else appends via stream_send with fin passed through. A
 * stream_send rejection (previous round not yet ACKed -- srvrun.h) drops
 * this one round for this subscriber, counted on the hub: voice is
 * loss-tolerant, and chat's rounds are paced far apart enough that in
 * practice only voice hits it. Sustained rejection sheds the stream
 * entirely (moqtrun_relay_note_busy) -- delivering the newest frame beats
 * faithfully replaying a stale backlog. */
static void moqtrun_relay_forward_one(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    usz                  i,
    wired_span           wire,
    int                  fin) {
  if (moqtrun_is_bare_fin(wire, fin)) {
    hub->io.stream_fin(wt, relay->sub_stream_id[i]);
    return;
  }
  if (hub->io.stream_send(wt, relay->sub_stream_id[i], wire, fin) == 1) {
    hub->stat_relay_sent++;
    relay->sub_busy_streak[i] = 0;
    return;
  }
  moqtrun_relay_note_busy(hub, wt, relay, i);
}

/* 1 iff a late open would be pointless: the round at hand already ends the
 * stream (opening one just to close it delivers nothing), or no header was
 * saved to open it with. */
static int moqtrun_late_open_skip(const wired_moqtrun_relay* relay, int fin) {
  return fin || relay->hdr_len == 0;
}

/* A subscriber that joined AFTER this relay started (its slot never
 * opened): open its stream now, carrying the saved SUBGROUP_HEADER bytes
 * alone -- the current round's Objects are dropped for this late joiner
 * (voice is loss-tolerant; the next round appends normally, and the
 * header-only first chunk is a well-formed stream head for the client's
 * incremental decoder). */
static void moqtrun_relay_late_open(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  dst,
    wired_moqtrun_relay* relay,
    usz                  i,
    int                  fin) {
  if (moqtrun_late_open_skip(relay, fin)) return;
  i64 sid = hub->io.open_uni_stream(
      dst->wt, wired_span_of(relay->hdr, relay->hdr_len));
  if (sid < 0) {
    hub->stat_open_drop++;
    return;
  }
  relay->sub_stream_id[i]   = (u64)sid;
  relay->sub_stream_set[i]  = 1;
  relay->sub_busy_streak[i] = 0;
}

/* One subscriber's share of a relayed round: forward to its open stream,
 * or -- for a subscriber whose stream was never opened (it subscribed
 * after the relay started) -- open one now (moqtrun_relay_late_open). */
static void moqtrun_relay_append_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    wired_span           wire,
    int                  fin) {
  wired_moqtrun_peer* dst = &hub->peers[sub->session_idx];
  if (!dst->in_use) return;
  if (relay->sub_stream_set[i]) {
    moqtrun_relay_forward_one(hub, dst->wt, relay, i, wire, fin);
    return;
  }
  moqtrun_relay_late_open(hub, dst, relay, i, fin);
}

static void moqtrun_relay_append_all(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           wire,
    int                  fin) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (track->subs[i].active)
      moqtrun_relay_append_one(hub, &track->subs[i], relay, i, wire, fin);
}

/* Saves the undelivered tail (bytes past the last complete Object) as the
 * relay's fragment for the next delivery. A tail larger than one whole
 * Object can never complete (WIRED_MOQTRUN_RELAY_FRAG_MAX is the largest
 * relayable Object) -- drop it (counted on the hub), degrading to a torn
 * frame for this one stream rather than corrupting the relay's own state. */
static void moqtrun_relay_save_frag(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, const u8* p, usz n) {
  if (n > WIRED_MOQTRUN_RELAY_FRAG_MAX) {
    relay->frag_len = 0;
    hub->stat_frag_drop++;
    return;
  }
  bytes_memcpy(relay->frag, p, n);
  relay->frag_len = n;
}

/* Object-boundary normalization (wired_moqtrun_relay's frag doc): prepends
 * the relay's held fragment to this delivery in hub->relay_scratch, finds
 * the last complete Object boundary, keeps the tail past it as the next
 * fragment, and returns the whole-Objects prefix -- the only bytes safe to
 * forward, because a forwarded round can be dropped per subscriber and a
 * dropped round must never end mid-Object. hdr type 0 is the right decode
 * context here for the same reason it was for the former known-stream
 * resolver: every relayed stream's header has the Properties bit off. */
static wired_span moqtrun_relay_normalize(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, wired_span data) {
  usz            total = relay->frag_len + data.n;
  moqdata_subhdr hdr   = {0};
  usz            off   = 0;
  bytes_memcpy(hub->relay_scratch, relay->frag, relay->frag_len);
  bytes_memcpy(hub->relay_scratch + relay->frag_len, data.p, data.n);
  moqtrun_decode_object_loop(
      wired_span_of(hub->relay_scratch, total), &off, &hdr);
  moqtrun_relay_save_frag(hub, relay, hub->relay_scratch + off, total - off);
  return wired_span_of(hub->relay_scratch, off);
}

/* 1 if this normalized round carries anything worth forwarding: whole
 * Objects, or the publisher's FIN (which must reach the subscriber streams
 * even with no bytes of its own). */
static int moqtrun_relay_round_due(wired_span whole, int fin) {
  return whole.n != 0 || fin;
}

/* ========== reliable relay: ring-backed forwarding (moqtrel) ==========
 * A track whose own_alias is below hub->reliable_alias_limit forwards
 * through a moqtrel ring instead of the drop-on-refusal path above:
 * refused sends retry from the ring on later ticks, and the publisher's
 * receive credit is held (io.stream_hold) when the ring nears capacity --
 * bytes are delayed, never dropped, for every subscriber that keeps up.
 * The ring module only decides (moqtrel.h); every io call stays here. */

static int moqtrun_track_is_reliable(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  return t->own_alias < hub->reliable_alias_limit;
}

/* First free ring in the pool, or 0 (the caller falls back to lossy). */
static moqtrel_buf* moqtrun_rel_acquire(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTREL_POOL; i++)
    if (!hub->rel_pool[i].in_use) return &hub->rel_pool[i];
  return 0;
}

/* Ring append, counting the by-design-impossible refusal: the hold
 * watermark keeps free space ahead of the publisher's window, so a full
 * ring is an invariant violation to record (stat_rel_overflow, the
 * reliable twin of stat_frag_drop), not a loss to handle. */
static void moqtrun_rel_take(
    wired_moqt_hub* hub, moqtrel_buf* rb, wired_span whole) {
  if (whole.n == 0) return;
  if (!moqtrel_append(rb, whole)) hub->stat_rel_overflow++;
}

/* Binds a free ring to relay for a reliable track: the publisher recorded
 * for the hold/release calls, the opening round (header + whole Objects)
 * appended so cursor offsets match the true stream offsets. An exhausted
 * pool counts stat_relay_full and leaves rel_idx -1: the caller's lossy
 * start continues unchanged (the fallback path). */
static void moqtrun_rel_bind(
    wired_moqt_hub*      hub,
    wired_moqtrun_relay* relay,
    wired_wt_session*    pub_wt,
    u64                  pub_stream_id,
    wired_span           head) {
  moqtrel_buf* rb = moqtrun_rel_acquire(hub);
  if (!rb) {
    hub->stat_relay_full++; /* pool dry: this stream relays lossily */
    return;
  }
  moqtrel_reset(rb);
  rb->in_use     = 1;
  rb->pub        = pub_wt;
  rb->pub_stream = pub_stream_id;
  moqtrun_rel_take(hub, rb, head);
  relay->rel_idx = (i32)(rb - hub->rel_pool);
}

/* Reliable gate for a fresh keep-open stream: only a track below the
 * alias limit, and only when the io table can actually hold the
 * publisher back (without stream_hold a ring would only overflow). */
static void moqtrun_rel_start(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_wt_session*    pub_wt,
    u64                  pub_stream_id,
    wired_span           head) {
  if (!hub->io.stream_hold || !moqtrun_track_is_reliable(hub, track)) return;
  moqtrun_rel_bind(hub, relay, pub_wt, pub_stream_id, head);
}

/* Activates sub slot i's ring cursor if its relay stream opened: the
 * opening round already carried every byte appended so far, so the
 * cursor starts at tail; the stall clock anchors at the last tick. */
static void moqtrun_rel_attach_sub(
    moqtrel_buf*               rb,
    const wired_moqtrun_track* track,
    const wired_moqtrun_relay* relay,
    usz                        i,
    u64                        now_ms) {
  if (!track->subs[i].active || !relay->sub_stream_set[i]) return;
  rb->subs[i].active     = 1;
  rb->subs[i].sent       = rb->tail;
  rb->subs[i].last_ok_ms = now_ms;
}

/* After the opening moqtrun_relay_open_all: record each subscriber stream
 * that actually opened as a ring cursor. A slot that failed to open, or
 * subscribes later, never rides this ring -- it keeps the lossy late-open
 * behavior (saved header only). */
static void moqtrun_rel_attach_subs(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay) {
  if (relay->rel_idx < 0) return;
  moqtrel_buf* rb = &hub->rel_pool[relay->rel_idx];
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    moqtrun_rel_attach_sub(rb, track, relay, i, hub->live.last_now_ms);
}

/* 1 while cursor i still expects delivery work (live, not given up on,
 * not yet FIN'd) -- the && chain lives here for the CCN gate. */
static int moqtrun_rel_sub_open(const moqtrel_buf* rb, usz i) {
  return rb->subs[i].active && !rb->subs[i].shed && !rb->subs[i].fin_done;
}

/* Destination peer for cursor i's sends, or 0 when the cursor has no
 * work (indexing peers[] on an inactive slot would read a garbage
 * session_idx -- same guard as every other session_idx use here) or the
 * peer vanished (skipped, retried next tick). */
static wired_moqtrun_peer* moqtrun_rel_sub_dst(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* track,
    const moqtrel_buf*         rb,
    usz                        i) {
  if (!moqtrun_rel_sub_open(rb, i)) return 0;
  wired_moqtrun_peer* dst = &hub->peers[track->subs[i].session_idx];
  return dst->in_use ? dst : 0;
}

/* Gives up on stalled sub slot i: reset its relay stream and mark the
 * cursor shed so it stops pinning the ring. Unlike the lossy shed, a
 * reliable shed never re-opens, so a refused reset is not retried -- it
 * only costs that peer a dangling stream. */
static void moqtrun_rel_shed(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i) {
  hub->io.stream_reset(wt, relay->sub_stream_id[i], 0);
  rb->subs[i].shed = 1;
  hub->stat_rel_stall++;
}

/* The publisher's FIN reached cursor i with no bytes pending: close its
 * stream via the byte-less stream_fin (the io contract forbids an empty
 * stream_send). A refusal retries next tick. */
static void moqtrun_rel_try_fin(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i) {
  if (!rb->fin_seen) return;
  if (hub->io.stream_fin(wt, relay->sub_stream_id[i]) == 1)
    rb->subs[i].fin_done = 1;
}

/* 1 when this round's last byte is the stream's last byte ever: the
 * send can carry the closing FIN itself. */
static int moqtrun_rel_round_fins(const moqtrel_buf* rb, usz i, usz n) {
  return rb->fin_seen && rb->subs[i].sent + n == rb->tail;
}

/* An accepted round: advance the cursor (restarting its stall clock) and
 * mark the FIN done when the round carried it. */
static void moqtrun_rel_round_ok(
    moqtrel_buf* rb, usz i, usz n, int fin_flag, u64 now_ms) {
  moqtrel_note_sent(rb, i, (usz)n, now_ms);
  if (fin_flag) rb->subs[i].fin_done = 1;
}

/* One send round for cursor i: the ring's next contiguous span, the FIN
 * riding the last one. A refusal changes nothing -- the same span
 * retries on a later tick (delayed, never dropped). */
static void moqtrun_rel_send_round(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u64                  now_ms) {
  wired_span span = moqtrel_next_round(rb, (u32)i);
  if (span.n == 0) { /* caught up: only the FIN can remain */
    moqtrun_rel_try_fin(hub, wt, relay, rb, i);
    return;
  }
  int fin_flag = moqtrun_rel_round_fins(rb, i, span.n);
  if (hub->io.stream_send(wt, relay->sub_stream_id[i], span, fin_flag) == 1)
    moqtrun_rel_round_ok(rb, i, span.n, fin_flag, now_ms);
}

/* Cursor i's whole drain turn: skip one with nothing to do or a vanished
 * destination, shed a stalled one, send one round otherwise. */
static void moqtrun_rel_drain_sub(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u64                  now_ms) {
  wired_moqtrun_peer* dst = moqtrun_rel_sub_dst(hub, track, rb, i);
  if (!dst) return;
  if (moqtrel_stalled(rb, (u32)i, now_ms)) {
    moqtrun_rel_shed(hub, dst->wt, relay, rb, i);
    return;
  }
  moqtrun_rel_send_round(hub, dst->wt, relay, rb, i, now_ms);
}

/* Backpressure release: enough drained -- give the publisher its credit
 * back. held is only ever set through a non-null stream_hold (the gate
 * in moqtrun_rel_start), so no null check is needed. */
static void moqtrun_rel_maybe_release(wired_moqt_hub* hub, moqtrel_buf* rb) {
  if (!rb->held || !moqtrel_should_release(rb)) return;
  hub->io.stream_hold(rb->pub, rb->pub_stream, 0);
  rb->held = 0;
}

/* Every cursor delivered or given up: the ring returns to the pool and
 * the relay entry frees. A still-applied hold is released first -- an
 * all-shed ring can finish while the publisher still sends, and its
 * receive credit must not stay frozen forever. */
static void moqtrun_rel_maybe_done(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, moqtrel_buf* rb) {
  if (!moqtrel_all_done(rb)) return;
  if (rb->held) hub->io.stream_hold(rb->pub, rb->pub_stream, 0);
  rb->in_use     = 0;
  relay->rel_idx = -1;
  relay->in_use  = 0;
}

/* One full drain pass over a ring: a round per open cursor, reclaim what
 * every live cursor has passed, then the two closing decisions (release
 * the hold once enough drained, return everything once every cursor is
 * delivered or given up). */
static void moqtrun_rel_drain_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    u64                  now_ms) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    moqtrun_rel_drain_sub(hub, track, relay, rb, i, now_ms);
  moqtrel_reclaim(rb);
  moqtrun_rel_maybe_release(hub, rb);
  moqtrun_rel_maybe_done(hub, relay, rb);
}

/* Backpressure hold, decided on the post-drain fill so a round that
 * empties the ring never holds at all. in_use guards the ring
 * moqtrun_rel_maybe_done freed a moment earlier; a bound ring implies a
 * non-null stream_hold (the moqtrun_rel_start gate). */
static void moqtrun_rel_maybe_hold(wired_moqt_hub* hub, moqtrel_buf* rb) {
  if (!rb->in_use || !moqtrel_should_hold(rb)) return;
  hub->io.stream_hold(rb->pub, rb->pub_stream, 1);
  rb->held = 1;
}

/* A later delivery on a ring-backed relay: append the whole-Object bytes
 * (the Object-boundary rounding is shared with the lossy path), record
 * the publisher's FIN, drain this ring now, and decide the hold. */
static void moqtrun_rel_continue(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           whole,
    int                  fin) {
  moqtrel_buf* rb = &hub->rel_pool[relay->rel_idx];
  moqtrun_rel_take(hub, rb, whole);
  if (fin) rb->fin_seen = 1;
  moqtrun_rel_drain_one(hub, track, relay, rb, hub->live.last_now_ms);
  moqtrun_rel_maybe_hold(hub, rb);
}

/* wired_moqt_tick's reliable-relay walk: drain every ring-backed relay so
 * refused rounds retry, stalls shed, and holds release on the clock, not
 * only when the publisher happens to deliver again. */
static void moqtrun_rel_tick_relay(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    u64                  now_ms) {
  if (!relay->in_use || relay->rel_idx < 0) return;
  moqtrun_rel_drain_one(
      hub, track, relay, &hub->rel_pool[relay->rel_idx], now_ms);
}

static void moqtrun_rel_tick_track(
    wired_moqt_hub* hub, wired_moqtrun_track* track, u64 now_ms) {
  if (!track->in_use) return;
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++)
    moqtrun_rel_tick_relay(hub, track, &track->relays[r], now_ms);
}

static void moqtrun_rel_tick_peer(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 now_ms) {
  if (!p->in_use) return;
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    moqtrun_rel_tick_track(hub, &p->tracks[t], now_ms);
}

static void moqtrun_rel_tick_all(wired_moqt_hub* hub, u64 now_ms) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    moqtrun_rel_tick_peer(hub, &hub->peers[i], now_ms);
}

/* ============== end of the reliable-relay (moqtrel) block ============== */

/* The pre-existing drop-on-refusal continue, byte-for-byte: forward the
 * round and free the entry at the publisher's FIN. */
static void moqtrun_relay_continue_lossy(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           whole,
    int                  fin) {
  if (moqtrun_relay_round_due(whole, fin))
    moqtrun_relay_append_all(hub, track, relay, whole, fin);
  if (fin) relay->in_use = 0;
}

/* A later call on an already-relayed publisher stream: forward its
 * whole-Object bytes (moqtrun_relay_normalize) to every subscriber-side
 * stream this relay opened, and free the entry once the publisher's FIN
 * has been forwarded (the subscriber streams are closed by that same
 * round; a fragment still held at FIN time is a torn tail with no
 * continuation coming -- dropped). A ring-backed relay (rel_idx >= 0)
 * takes the reliable path instead: its bytes are retried, not dropped,
 * and its entry lives until every cursor is delivered or given up. */
static void moqtrun_relay_continue(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           wire,
    int                  fin) {
  wired_span whole = moqtrun_relay_normalize(hub, relay, wire);
  if (relay->rel_idx >= 0) {
    moqtrun_rel_continue(hub, track, relay, whole, fin);
    return;
  }
  moqtrun_relay_continue_lossy(hub, track, relay, whole, fin);
}

/* Opens sub slot i's relay stream carrying wire as its first round and
 * records the id for later moqtrun_relay_append_one calls. An open failure
 * (no free send slot on that connection) leaves the slot unset: later
 * rounds skip this subscriber (moqtrun_relay_sub_ready). */
static void moqtrun_relay_open_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    wired_span           wire) {
  wired_moqtrun_peer* dst = &hub->peers[sub->session_idx];
  if (!dst->in_use) return;
  i64 sid = hub->io.open_uni_stream(dst->wt, wire);
  if (sid < 0) {
    hub->stat_open_drop++;
    return;
  }
  relay->sub_stream_id[i]   = (u64)sid;
  relay->sub_stream_set[i]  = 1;
  relay->sub_busy_streak[i] = 0;
}

static void moqtrun_relay_open_all(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           wire) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (track->subs[i].active)
      moqtrun_relay_open_one(hub, &track->subs[i], relay, i, wire);
}

/* Saves the stream's SUBGROUP_HEADER bytes on relay for late-joining
 * subscribers (moqtrun_relay_late_open). data starts with the header --
 * this is only called for a stream that already classified and decoded as
 * SUBGROUP, so a decode failure here cannot really happen; it just leaves
 * hdr_len 0 (late joiners are then skipped rather than sent garbage). */
static void moqtrun_relay_save_hdr(
    wired_moqtrun_relay* relay, wired_span data) {
  usz            off = 0;
  moqdata_subhdr hdr;
  relay->hdr_len = 0;
  if (moqdata_subhdr_take(data, &off, &hdr) != MOQDATA_OK) return;
  if (off > WIRED_MOQTRUN_RELAY_HDR_MAX) return;
  bytes_memcpy(relay->hdr, data.p, off);
  relay->hdr_len = off;
}

/* Starts relaying a fresh publisher stream that stays open past this call
 * (fin=0): claims a relay entry keyed by pub_stream_id and opens one
 * keep-open uni stream per subscriber carrying wire as the first round.
 * Every entry busy -> this stream is not relayed at all (its subscribers
 * miss it; WIRED_MOQTRUN_MAX_RELAYS is sized so this only happens under a
 * burst the room's own pacing never produces). A reliable track's stream
 * (moqtrun_rel_start) additionally binds a ring and records each opened
 * subscriber stream as a ring cursor (moqtrun_rel_attach_subs); the open
 * calls themselves are shared with the lossy path. */
static void moqtrun_relay_start(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_wt_session*    pub_wt,
    u64                  pub_stream_id,
    wired_span           wire,
    usz                  whole_end) {
  wired_moqtrun_relay* relay = moqtrun_relay_alloc(track);
  if (!relay) {
    hub->stat_relay_full++; /* whole message lost for every subscriber */
    return;
  }
  relay->in_use        = 1;
  relay->pub_stream_id = pub_stream_id;
  relay->rel_idx       = -1; /* lossy until moqtrun_rel_start binds a ring */
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    relay->sub_stream_set[i]  = 0;
    relay->sub_busy_streak[i] = 0; /* freestanding memory starts unzeroed */
  }
  relay->frag_len = 0;
  moqtrun_rel_start(
      hub, track, relay, pub_wt, pub_stream_id,
      wired_span_of(wire.p, whole_end));
  moqtrun_relay_save_frag(hub, relay, wire.p + whole_end, wire.n - whole_end);
  moqtrun_relay_save_hdr(relay, wire);
  moqtrun_relay_open_all(hub, track, relay, wired_span_of(wire.p, whole_end));
  moqtrun_rel_attach_subs(hub, track, relay);
}

/* Decodes the SUBGROUP_HEADER + the one Object this subset always sends
 * whole in one call (1 message = 1 Object = 1 Group = 1
 * Subgroup). Returns 1 and fills *hdr on a fully decoded Object, 0
 * otherwise (nothing to relay -- covers INSUFFICIENT/VIOLATION alike, since
 * a hub-internal relay has no peer to report a VIOLATION to at this call
 * site). */
/* Decodes every complete Object following an already-decoded
 * SUBGROUP_HEADER (hdr, *off already past it), advancing *off past each one
 * in turn. Stops at the first Object that does not fully decode (buffer
 * ran out mid-Object, or a VIOLATION-shaped Object) -- *off is left at the
 * end of the last successfully decoded Object, never mid-Object
 * (moqdata_obj_take leaves *off unchanged on any non-OK result).
 * Returns the count of Objects decoded (0 if the very first one fails --
 * nothing to relay). A single-Object stream decodes identically to this
 * hub's former one-shot-Object path, this is that path's generalization to
 * N Objects on one stream. */
static usz moqtrun_decode_object_loop(
    wired_span data, usz* off, const moqdata_subhdr* hdr) {
  moqdata_objseq seq = moqdata_objseq_of(hdr->type);
  usz            n   = 0;
  while (*off < data.n) {
    moqdata_obj obj;
    if (moqdata_obj_take(data, off, &seq, &obj) != MOQDATA_OK) break;
    n++;
  }
  return n;
}

static int moqtrun_track_has_alias(
    const wired_moqtrun_track* t, u64 track_alias) {
  return t->in_use && t->own_alias == track_alias;
}

/* Finds p's own track slot whose PUBLISH declared track_alias, else 0 --
 * resolves an inbound SUBGROUP_HEADER's Track Alias to which of p's
 * (chat/audio) tracks the Object belongs to. */
static wired_moqtrun_track* moqtrun_track_by_alias(
    wired_moqtrun_peer* p, u64 track_alias) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    if (moqtrun_track_has_alias(&p->tracks[t], track_alias))
      return &p->tracks[t];
  return 0;
}

/* 1 iff a fresh delivery has nothing worth relaying at all: no complete
 * Object AND the stream ends here (fin) -- no continuation can ever finish
 * the torn head. Without fin the header alone is worth accepting: the torn
 * head becomes the relay's first fragment and later deliveries complete it
 * (a keep-open stream whose first slice tore mid-Object used to be dropped
 * outright, orphaning every later header-less delivery on it). */
static int moqtrun_fresh_nothing_due(usz whole_objects, int fin) {
  return whole_objects == 0 && fin;
}

/* SUBGROUP_HEADER + every following Object, for a stream already
 * confirmed to classify as SUBGROUP -- split out of moqtrun_resolve_fresh_
 * stream_track to keep that function's own branch count at the CCN gate.
 * *whole_end receives the end of the last COMPLETE Object (the fresh
 * stream's own normalization boundary, moqtrun_relay_normalize's twin for
 * the opening delivery); with zero complete Objects it is the header's
 * end, accepted only when more deliveries are coming (fin=0,
 * moqtrun_fresh_nothing_due). */
static wired_moqtrun_track* moqtrun_decode_fresh_subgroup(
    wired_moqtrun_peer* p, wired_span data, usz* whole_end, int fin) {
  usz            off = 0;
  moqdata_subhdr hdr;
  if (moqdata_subhdr_take(data, &off, &hdr) != MOQDATA_OK) return 0;
  if (moqtrun_fresh_nothing_due(
          moqtrun_decode_object_loop(data, &off, &hdr), fin))
    return 0;
  *whole_end = off;
  return moqtrun_track_by_alias(p, hdr.track_alias);
}

/* Classifies a FRESH data stream's leading Stream Type varint and, for
 * SUBGROUP_HEADER, decodes the header + every following Object,
 * resolving the header's Track Alias to one of p's (chat/audio) track
 * slots -- else 0 (not a SUBGROUP stream, header decode failure, zero
 * Objects decoded on a one-shot fin delivery, or an unknown Track
 * Alias). */
static wired_moqtrun_track* moqtrun_resolve_fresh_stream_track(
    wired_moqtrun_peer* p, wired_span data, usz* whole_end, int fin) {
  usz classify_off = 0;
  int kind         = moqdata_classify(data, &classify_off);
  if (kind != MOQDATA_STREAM_SUBGROUP) return 0;
  return moqtrun_decode_fresh_subgroup(p, data, whole_end, fin);
}

/* A publisher stream seen for the first time: resolve its track from the
 * SUBGROUP_HEADER, then either relay it whole as one-shot streams (its FIN
 * arrived with the data -- nothing more will follow, so a torn tail has no
 * continuation either and rides along harmlessly) or start a keep-open
 * relay entry for the rounds still to come (moqtrun_relay_start, which
 * holds the tail back as the first fragment). Padding streams, other
 * classifications, and unknown Track Aliases are discarded:
 * classification-level session closes are the sess layer's job. */
static void moqtrun_dispatch_fresh_stream(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  usz                  whole_end = 0;
  wired_moqtrun_track* track =
      moqtrun_resolve_fresh_stream_track(p, data, &whole_end, fin);
  if (!track) return;
  if (fin) {
    moqtrun_relay_object(hub, track, data);
    return;
  }
  moqtrun_relay_start(hub, track, p->wt, stream_id, data, whole_end);
}

/* draft 3.4/11.4.2: relay a data stream's bytes verbatim to the
 * subscribers of the track its Track Alias names. A stream_id already in
 * the relay map (an earlier call on this same publisher stream) forwards
 * straight to its recorded subscriber streams -- no re-classification, no
 * header re-decode (later calls carry bare Objects, or nothing at all for
 * a bare FIN). Anything else is treated as fresh. */
static void moqtrun_dispatch_data_stream(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  wired_moqtrun_track* track = 0;
  wired_moqtrun_relay* relay =
      moqtrun_peer_relay_by_stream(p, stream_id, &track);
  if (relay) {
    moqtrun_relay_continue(hub, track, relay, data, fin);
    return;
  }
  moqtrun_dispatch_fresh_stream(hub, p, stream_id, data, fin);
}

/* ===================== public entry points ===================== */

void wired_moqt_on_stream_data(
    void*             app_ctx,
    wired_wt_session* s,
    u64               stream_id,
    wired_span        data,
    int               fin) {
  wired_moqt_hub*     hub = (wired_moqt_hub*)app_ctx;
  wired_moqtrun_peer* p   = moqtrun_find_by_wt(hub, s);
  if (!p) return;
  if (stream_id == p->control_stream_id) {
    usz peer_idx = (usz)(p - hub->peers);
    moqtrun_dispatch_ctl_stream(hub, p, peer_idx, data);
    return;
  }
  moqtrun_dispatch_data_stream(hub, p, stream_id, data, fin);
}

/* ===================== OBJECT_DATAGRAM relay (draft 11.3) ============= */

/* The datagram plane is usable for this delivery: the sending session is
 * registered AND the io table actually has a send_datagram entry (0 in an
 * older positional initializer -- must never be dereferenced). */
static int moqtrun_dg_ready(const wired_moqt_hub* hub, const void* p) {
  return p != 0 && hub->io.send_datagram != 0;
}

/* Resolves one received OBJECT_DATAGRAM to the sending peer's track:
 * decode via moqdg_take (11.3.1), then the header's Track Alias via
 * moqtrun_track_by_alias. 0 when the datagram is malformed or the alias
 * matches none of p's tracks -- the caller drops it whole. */
static wired_moqtrun_track* moqtrun_dg_track(
    wired_moqtrun_peer* p, wired_span data) {
  usz       off = 0;
  moqdg_obj obj;
  if (moqdg_take(data, &off, &obj) != MOQDATA_OK) return 0;
  return moqtrun_track_by_alias(p, obj.track_alias);
}

/* One subscriber's copy: the SAME bytes, unmodified (the relay never
 * re-encodes). An accepted queue counts on stat_dg_sent, a refusal on
 * stat_dg_drop -- and that copy is simply gone (no retransmission, no
 * busy streak: the next audio frame arrives in ~20ms anyway). */
static void moqtrun_dg_to_one(
    wired_moqt_hub* hub, const wired_moqtrun_sub* sub, wired_span data) {
  wired_moqtrun_peer* dst = &hub->peers[sub->session_idx];
  if (!dst->in_use) return;
  if (hub->io.send_datagram(dst->wt, data) == 1)
    hub->stat_dg_sent++;
  else
    hub->stat_dg_drop++;
}

/* Stateless fan-out to every active subscriber of the track -- the
 * datagram twin of moqtrun_relay_object. A deactivated (closed)
 * subscription is skipped; late subscribers get nothing retroactively. */
static void moqtrun_dg_fanout(
    wired_moqt_hub* hub, const wired_moqtrun_track* track, wired_span data) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (track->subs[i].active) moqtrun_dg_to_one(hub, &track->subs[i], data);
}

void wired_moqt_on_datagram(
    void* app_ctx, wired_wt_session* s, wired_span data) {
  wired_moqt_hub*     hub = (wired_moqt_hub*)app_ctx;
  wired_moqtrun_peer* p   = moqtrun_find_by_wt(hub, s);
  if (!moqtrun_dg_ready(hub, p)) return;
  wired_moqtrun_track* track = moqtrun_dg_track(p, data);
  /* Malformed or unknown-alias: dropped whole. Draft 11.3.1 says an
   * invalid Type MUST close the session (PROTOCOL_VIOLATION), but this
   * hub's io table has no close operation -- counting is the closest. */
  if (!track) {
    hub->stat_dg_bad++;
    return;
  }
  moqtrun_dg_fanout(hub, track, data);
}

/* A ring-backed relay also deactivates the dead subscriber's ring
 * cursor, so the next drain reclaims past it (and can release a
 * publisher hold the leaver's backlog was causing). */
static void moqtrun_rel_clear_sub(
    wired_moqt_hub* hub, const wired_moqtrun_relay* r, usz si) {
  if (r->in_use && r->rel_idx >= 0)
    hub->rel_pool[r->rel_idx].subs[si].active = 0;
}

/* Clear every relay's record of subscriber slot si's stream, so a later
 * relay round neither appends to nor late-opens a stream on the dead
 * session. */
static void moqtrun_relays_clear_sub(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz si) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++) {
    t->relays[r].sub_stream_set[si] = 0;
    moqtrun_rel_clear_sub(hub, &t->relays[r], si);
  }
}

/* Deactivate track t's subscription entries held by peer index idx. */
static void moqtrun_track_drop_sub(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz idx) {
  for (usz si = 0; si < WIRED_MOQTRUN_MAX_SUBS; si++) {
    if (!moqtrun_sub_is_peer(&t->subs[si], idx)) continue;
    t->subs[si].active = 0;
    moqtrun_relays_clear_sub(hub, t, si);
  }
}

static void moqtrun_peer_drop_subs(
    wired_moqt_hub* hub, wired_moqtrun_peer* q, usz idx) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    if (q->tracks[t].in_use) moqtrun_track_drop_sub(hub, &q->tracks[t], idx);
}

/* The hub's own tracks (blob and live) forget peer index idx too: a
 * reconnect landing in the same slot must be served afresh, not mistaken
 * for the dead peer. */
static void moqtrun_hub_tracks_drop_sub(wired_moqt_hub* hub, usz idx) {
  if (hub->blob_track.in_use)
    moqtrun_track_drop_sub(hub, &hub->blob_track, idx);
  if (hub->live.track.in_use)
    moqtrun_track_drop_sub(hub, &hub->live.track, idx);
}

/* Deactivate every subscription any peer's tracks (and the hub's own
 * tracks) hold for peer index idx. */
static void moqtrun_drop_peer_subs(wired_moqt_hub* hub, usz idx) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (hub->peers[i].in_use) moqtrun_peer_drop_subs(hub, &hub->peers[i], idx);
  moqtrun_hub_tracks_drop_sub(hub, idx);
}

void wired_moqt_on_session_close(void* app_ctx, wired_wt_session* s) {
  wired_moqt_hub*     hub = (wired_moqt_hub*)app_ctx;
  wired_moqtrun_peer* p   = moqtrun_find_by_wt(hub, s);
  if (!p) return;
  moqtrun_drop_peer_subs(hub, (usz)(p - hub->peers));
  p->in_use = 0;
}
