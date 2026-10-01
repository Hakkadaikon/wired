#include "app/moqt/run/moqtrun.h"

#include "app/moqt/ctl/moqctl.h"
#include "app/moqt/data/moqdata.h"
#include "app/moqt/dgram/moqdg.h"
#include "app/moqt/vi/moqvi.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"

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
  hub->io                    = io;
  hub->join_seq_next         = 0;
  hub->authorize_subscribe   = 0;
  hub->authorize_ctx         = 0;
  hub->stat_frag_drop        = 0;
  hub->stat_relay_sent       = 0;
  hub->stat_relay_drop       = 0;
  hub->stat_open_drop        = 0;
  hub->stat_relay_reset      = 0;
  hub->stat_relay_full       = 0;
  hub->stat_dg_sent          = 0;
  hub->stat_dg_drop          = 0;
  hub->stat_dg_bad           = 0;
  hub->blob_track.in_use     = 0;
  hub->live.track.in_use     = 0;
  hub->live.last_now_ms      = 0;
  hub->stat_live_sent        = 0;
  hub->stat_live_drop        = 0;
  hub->reliable_alias_limit  = 0;
  hub->stat_rel_stall        = 0;
  hub->stat_rel_overflow     = 0;
  hub->stat_rel_wait         = 0;
  hub->stat_rel_sent         = 0;
  hub->stat_rel_refused      = 0;
  hub->stat_rel_rings        = 0;
  hub->stat_rel_in_bytes     = 0;
  hub->stat_rel_fin_in       = 0;
  hub->stat_rel_fin_out      = 0;
  hub->stat_rel_hold         = 0;
  hub->stat_rel_early_return = 0;
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
  p->join_seq        = hub->join_seq_next++;
  p->sub_names_n     = 0;
  p->sub_names_at    = 0;
  p->send_lens[0]    = 0;
  p->send_lens[1]    = 0;
  p->armed_idx       = 0;
  p->ctl_asm.n       = 0;
  p->ctl_asm.at      = 0;
  p->ctl_asm.skip    = 0;
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
  u8                   msg[WIRED_MOQTRUN_CTL_REPLY_MAX];
  moqctl_request_error e = {0};
  e.error_code           = code;
  usz n                  = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_REQUEST_ERROR,
      moqtrun_encode_request_error, &e);
  moqtrun_queue_reply(p, wired_span_of(msg, n));
}

/* Full Track Name as this hub keys peer tracks (draft 1.5): the encoded
 * Track Namespace plus the Track Name. */
typedef struct {
  wired_span ns;
  wired_span name;
} moqtrun_key;

/* f's key, its namespace encoded into ns_buf (WIRED_MOQTRUN_MAX_NS bytes).
 * A namespace that does not fit gets length WIRED_MOQTRUN_MAX_NS + 1,
 * which no stored namespace has: it matches nothing and is never stored. */
static moqtrun_key moqtrun_key_of(const moqctl_ftn* f, u8* ns_buf) {
  moqtrun_key k;
  usz         n = 0;
  if (!moqctl_ns_put(wired_mspan_of(ns_buf, WIRED_MOQTRUN_MAX_NS), &n, &f->ns))
    n = WIRED_MOQTRUN_MAX_NS + 1;
  k.ns   = wired_span_of(ns_buf, n);
  k.name = f->name;
  return k;
}

/* A hub-owned track's key: no namespace (matched by name only). */
static moqtrun_key moqtrun_key_name(wired_span name) {
  moqtrun_key k;
  k.ns   = wired_span_of(0, 0);
  k.name = name;
  return k;
}

/* 1 iff k cannot be stored: namespace or name past its capacity. */
static int moqtrun_key_oversized(moqtrun_key k) {
  return k.ns.n > WIRED_MOQTRUN_MAX_NS || k.name.n > WIRED_MOQTRUN_MAX_NAME;
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

/* Records k on t; k.ns fits (callers refuse an oversized key first). */
static void moqtrun_record_track_key(wired_moqtrun_track* t, moqtrun_key k) {
  moqtrun_record_track_name(t, k.name);
  bytes_memcpy(t->ns, k.ns.p, k.ns.n);
  t->ns_len = k.ns.n;
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

static int moqtrun_ns_eq(const u8* ns, usz ns_len, wired_span k) {
  return ns_len == k.n && moqtrun_bytes_eq(ns, k.p, k.n);
}

/* Full Track Name match: namespace AND name (draft 1.5). */
static int moqtrun_track_key_matches(
    const wired_moqtrun_track* t, moqtrun_key k) {
  return moqtrun_track_name_matches(t, k.name) &&
         moqtrun_ns_eq(t->ns, t->ns_len, k.ns);
}

/* Finds p's own track slot already PUBLISHed under Full Track Name k,
 * else 0. */
static wired_moqtrun_track* moqtrun_track_slot_for_name(
    wired_moqtrun_peer* p, moqtrun_key k) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    if (moqtrun_track_key_matches(&p->tracks[t], k)) return &p->tracks[t];
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
    wired_moqtrun_peer* p, moqtrun_key k) {
  wired_moqtrun_track* existing = moqtrun_track_slot_for_name(p, k);
  return existing ? existing : moqtrun_track_free_slot(p);
}

/* 1 iff sub-name ring entry i of p equals name. */
static int moqtrun_sub_name_eq(
    const wired_moqtrun_peer* p, usz i, moqtrun_key k) {
  return p->sub_name_lens[i] == k.name.n &&
         moqtrun_bytes_eq(p->sub_names[i], k.name.p, k.name.n) &&
         moqtrun_ns_eq(p->sub_ns[i], p->sub_ns_lens[i], k.ns);
}

/* 1 iff p has recorded a successful SUBSCRIBE for name. */
static int moqtrun_sub_name_known(const wired_moqtrun_peer* p, moqtrun_key k) {
  for (usz i = 0; i < p->sub_names_n; i++)
    if (moqtrun_sub_name_eq(p, i, k)) return 1;
  return 0;
}

static void moqtrun_sub_name_store(wired_moqtrun_peer* p, moqtrun_key k) {
  bytes_memcpy(p->sub_names[p->sub_names_at], k.name.p, k.name.n);
  p->sub_name_lens[p->sub_names_at] = k.name.n;
  bytes_memcpy(p->sub_ns[p->sub_names_at], k.ns.p, k.ns.n);
  p->sub_ns_lens[p->sub_names_at] = k.ns.n;
  p->sub_names_at = (u8)((p->sub_names_at + 1) % WIRED_MOQTRUN_SUB_NAMES);
  if (p->sub_names_n < WIRED_MOQTRUN_SUB_NAMES) p->sub_names_n++;
}

/* Remember a name p subscribed to, so a later REPUBLISH of it can
 * re-attach p (wired_moqtrun_peer.sub_names' doc). An oversized name could
 * never match a recorded track name, so it is not stored. */
static void moqtrun_note_sub_name(wired_moqtrun_peer* p, moqtrun_key k) {
  if (moqtrun_key_oversized(k)) return;
  if (moqtrun_sub_name_known(p, k)) return;
  moqtrun_sub_name_store(p, k);
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

/* Returns relay r's bound ring to the pool on a publisher-side teardown
 * (the publisher's session closed, or a re-PUBLISH abandoned its old
 * streams). Nothing else can return it: the tick skips a dead
 * publisher's relays, so a ring left bound here would stay in_use
 * forever and each mid-stream disconnect would drain the pool by one
 * until every reliable stream fell back to lossy. Deliberately io-free:
 * on a session close the publisher's connection -- and any receive-
 * credit hold on it -- dies with the session, and on a re-PUBLISH a
 * still-held old stream stays harmlessly frozen: the hold is per-stream
 * (wired_server_wt_stream_hold), the publisher abandoned that stream (a
 * new PUBLISH opens new ones), and a receive slot resets its hold flag
 * when claimed, so the freeze can never leak onto a new stream. */
static void moqtrun_rel_drop_ring(wired_moqt_hub* hub, wired_moqtrun_relay* r) {
  if (!r->in_use || r->rel_idx < 0) return;
  hub->rel_pool[r->rel_idx].in_use = 0;
  r->rel_idx                       = -1;
}

static void moqtrun_track_drop_rings(
    wired_moqt_hub* hub, wired_moqtrun_track* t) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++)
    moqtrun_rel_drop_ring(hub, &t->relays[r]);
}

static void moqtrun_peer_drop_rings(
    wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    moqtrun_track_drop_rings(hub, &p->tracks[t]);
}

/* Claims slot t for a PUBLISH naming name/track_alias: clears subs only on
 * a fresh (not-yet-in_use) slot, so a re-PUBLISH under the same name keeps
 * its existing subscribers (matching the prior single-track hub's
 * overwrite behavior). Relays always clear: a (re-)PUBLISH means the
 * publisher's old streams are gone (and freestanding memory starts
 * unzeroed, so a fresh slot's relays hold garbage until this) -- but any
 * of those old streams still open on a subscriber's transport are reset
 * first, not just forgotten (moqtrun_track_reset_stale_relays' own doc). */
/* ===== Largest Object (draft 10.2.16) ===== */

static int moqtrun_loc_newer(const wired_moqtrun_track* t, moqctl_loc l) {
  return !t->has_largest || moqctl_loc_less(t->largest, l);
}

/* Notes an Object at {group, object} published on t (0: no track). */
static void moqtrun_track_note(wired_moqtrun_track* t, u64 group, u64 object) {
  moqctl_loc l = {group, object};
  if (t && moqtrun_loc_newer(t, l)) {
    t->largest     = l;
    t->has_largest = 1;
  }
}

/* A relay MUST count the upstream PUBLISH's LARGEST_OBJECT (10.2.16). */
static void moqtrun_track_seed_largest(
    wired_moqtrun_track* t, const moqctl_params* params) {
  const moqctl_param* l =
      moqctl_params_find(params, MOQCTL_PARAM_LARGEST_OBJECT);
  if (l) moqtrun_track_note(t, l->loc.group, l->loc.object);
}

static void moqtrun_track_claim(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    moqtrun_key          k,
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
  t->in_use      = 1;
  t->own_alias   = track_alias;
  t->has_largest = 0; /* a new PUBLISH restarts the Largest */
  moqtrun_track_drop_rings(hub, t);
  moqtrun_track_clear_relays(t);
  moqtrun_record_track_key(t, k);
}

static void moqtrun_reattach_subs(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    usz                  pub_idx,
    moqtrun_key          k);

static wired_moqtrun_track* moqtrun_peer_track_for_name(
    wired_moqtrun_peer* p, moqtrun_key k);

static void moqtrun_rel_return_ring(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, moqtrel_buf* rb);

/* Returns relay r's bound ring to the pool AND releases the publisher
 * credit hold it may have placed (moqtrun_rel_return_ring). Unlike
 * moqtrun_rel_drop_ring's io-free teardown, a superseded publisher's
 * session is still live: a hold left on its stream would freeze it. */
static void moqtrun_relay_return_ring(
    wired_moqt_hub* hub, wired_moqtrun_relay* r) {
  if (!r->in_use || r->rel_idx < 0) return;
  moqtrun_rel_return_ring(hub, r, &hub->rel_pool[r->rel_idx]);
}

static void moqtrun_track_return_rings(
    wired_moqt_hub* hub, wired_moqtrun_track* t) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++)
    moqtrun_relay_return_ring(hub, &t->relays[r]);
}

/* Frees a superseded track: its subscribers' still-open relay streams are
 * reset (moqtrun_track_reset_stale_relays' own doc), its rings go back to
 * the pool (holds released), and the slot stops matching any name or Track
 * Alias, so the lingering session's stray Objects are dropped instead of
 * relayed. */
static void moqtrun_track_retire(wired_moqt_hub* hub, wired_moqtrun_track* t) {
  moqtrun_track_reset_stale_relays(hub, t);
  moqtrun_track_return_rings(hub, t);
  moqtrun_track_clear_relays(t);
  t->in_use = 0;
}

/* Peer i's track keyed k, unless i is the publisher itself. */
static wired_moqtrun_track* moqtrun_other_track_for_name(
    wired_moqt_hub* hub, usz i, usz pub_idx, moqtrun_key k) {
  return i != pub_idx ? moqtrun_peer_track_for_name(&hub->peers[i], k) : 0;
}

/* 1 iff peer i, a NEWER session than the publisher (higher join_seq),
 * already holds a track named name. */
static int moqtrun_newer_owner(
    wired_moqt_hub* hub, usz i, usz pub_idx, moqtrun_key k) {
  return moqtrun_other_track_for_name(hub, i, pub_idx, k) != 0 &&
         hub->peers[i].join_seq > hub->peers[pub_idx].join_seq;
}

static int moqtrun_newer_holds_name(
    wired_moqt_hub* hub, usz pub_idx, moqtrun_key k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (moqtrun_newer_owner(hub, i, pub_idx, k)) return 1;
  return 0;
}

/* Name ownership policy (no auth on PUBLISH): the NEWEST session holding
 * a name owns it -- the same participant id opened in two tabs means the
 * newer tab wins. A participant that rejoins while its old session still
 * lingers (no clean close reached the hub, so it stays until the idle
 * timeout) PUBLISHes the same name twice; every OLDER peer's same-name
 * track is retired, so SUBSCRIBE resolves to the live track only and the
 * old track's subscribers follow via moqtrun_reattach_subs. Callers first
 * refuse a PUBLISH a newer peer already owns (moqtrun_publish_slot), so
 * arrival order never lets a stale session take the name back. */
static void moqtrun_supersede_name(
    wired_moqt_hub* hub, usz pub_idx, moqtrun_key k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    wired_moqtrun_track* t = moqtrun_other_track_for_name(hub, i, pub_idx, k);
    if (t) moqtrun_track_retire(hub, t);
  }
}

/* p's slot for a PUBLISH of name (moqtrun_track_alloc_slot), or 0 when
 * a newer session already owns name. Refusing -- rather than accepting
 * without superseding -- keeps every name on at most one live track: two
 * would make SUBSCRIBE resolve by peer-slot order, the stale-mapping bug
 * moqtrun_supersede_name exists to prevent. The refused, older session is
 * stale by definition (its client has moved on to the newer one). */
static wired_moqtrun_track* moqtrun_publish_slot(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, moqtrun_key k) {
  if (moqtrun_key_oversized(k)) return 0;
  if (moqtrun_newer_holds_name(hub, peer_idx, k)) return 0;
  return moqtrun_track_alloc_slot(p, k);
}

/* draft SS10.9 PUBLISH: accept a track into a free (or matching-name) slot
 * and reply REQUEST_OK; a third distinct track name (no free slot), or a
 * name a newer session already owns (moqtrun_publish_slot), gets
 * REQUEST_ERROR instead of silently overwriting an existing track. */
static void moqtrun_handle_publish(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  usz            off = 0;
  moqctl_publish m;
  u8             ns_buf[WIRED_MOQTRUN_MAX_NS];
  if (moqctl_publish_take(body, &off, &m) != MOQCTL_OK) return;
  moqtrun_key          k = moqtrun_key_of(&m.name, ns_buf);
  wired_moqtrun_track* t = moqtrun_publish_slot(hub, p, peer_idx, k);
  if (!t) {
    moqtrun_send_request_error(p, MOQCTL_ERR_NOT_SUPPORTED);
    return;
  }
  moqtrun_supersede_name(hub, peer_idx, k);
  moqtrun_track_claim(hub, t, k, m.track_alias);
  moqtrun_track_seed_largest(t, &m.params);
  moqtrun_reattach_subs(hub, t, peer_idx, k);
  u8                msg[WIRED_MOQTRUN_CTL_REPLY_MAX];
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
    wired_moqtrun_peer* p, moqtrun_key k) {
  return p->in_use ? moqtrun_track_slot_for_name(p, k) : 0;
}

/* Finds the track whose PUBLISHed Full Track Name (namespace AND name,
 * draft 1.5) equals the SUBSCRIBE's, across every connected peer. */
static wired_moqtrun_track* moqtrun_find_published_track(
    wired_moqt_hub* hub, moqtrun_key k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    wired_moqtrun_track* t = moqtrun_peer_track_for_name(&hub->peers[i], k);
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
    moqtrun_key           k) {
  if (!moqtrun_reattach_peer_live(hub, i, pub_idx)) return 0;
  if (moqtrun_track_sub_of_peer(t, i)) return 0;
  return moqtrun_sub_name_known(&hub->peers[i], k);
}

/* ===== subscription state (draft 10.6 SUBSCRIBE parameters) ===== */

static const moqctl_param* moqtrun_sub_param(
    const moqctl_subscribe* m, u64 type) {
  return m ? moqctl_params_find(&m->params, type) : 0;
}

static u8 moqtrun_param_u8(const moqctl_param* p) { return p ? (u8)p->u8v : 0; }

static u64 moqtrun_param_vi(const moqctl_param* p) { return p ? p->vi : 0; }

/* FORWARD omitted defaults to 1 (10.2.17). */
static u8 moqtrun_forward_off(const moqctl_param* p) {
  return p && p->u8v == 0;
}

/* Filter Start Location per type (9.3.1), indexed by MOQCTL_FILTER_*:
 * Largest-relative ones resolve against t's Largest now, {0, 0} when
 * nothing was published; Absolute ones take the given start. */
typedef moqctl_loc (*moqtrun_start_fn)(const wired_moqtrun_track*, moqctl_loc);

static moqctl_loc moqtrun_start_given(
    const wired_moqtrun_track* t, moqctl_loc start) {
  (void)t;
  return start;
}

static moqctl_loc moqtrun_start_next_group(
    const wired_moqtrun_track* t, moqctl_loc start) {
  moqctl_loc l = {0, 0};
  (void)start;
  if (t->has_largest) l.group = t->largest.group + 1;
  return l;
}

static moqctl_loc moqtrun_start_largest(
    const wired_moqtrun_track* t, moqctl_loc start) {
  moqctl_loc l = {0, 0};
  (void)start;
  if (!t->has_largest) return l;
  l = t->largest;
  l.object++;
  return l;
}

static const moqtrun_start_fn MOQTRUN_START_FNS[5] = {
    moqtrun_start_given, moqtrun_start_next_group, moqtrun_start_largest,
    moqtrun_start_given, moqtrun_start_given};

/* LOCATION_FILTER f (0: unfiltered, start {0, 0}) resolved onto s. The
 * decoder admits only types 1-4 (moqctl_locfilter_take). */
static void moqtrun_sub_filter(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* f) {
  moqctl_loc zero  = {0, 0};
  s->start         = zero;
  s->has_end_group = 0;
  if (!f) return;
  s->start         = MOQTRUN_START_FNS[f->lf.type](t, f->lf.start);
  s->has_end_group = f->lf.type == MOQCTL_FILTER_ABS_RANGE;
  s->end_group     = s->start.group + f->lf.end_group_delta;
}

/* Priority and group order are recorded only; delivery is not reordered
 * by them yet. */
static void moqtrun_sub_scalars(
    wired_moqtrun_sub* s, const moqctl_subscribe* m) {
  const moqctl_param* pr =
      moqtrun_sub_param(m, MOQCTL_PARAM_SUBSCRIBER_PRIORITY);
  const moqctl_param* dt =
      moqtrun_sub_param(m, MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT);
  s->priority     = moqtrun_param_u8(pr);
  s->has_priority = pr != 0;
  s->group_order =
      moqtrun_param_u8(moqtrun_sub_param(m, MOQCTL_PARAM_GROUP_ORDER));
  s->forward_off =
      moqtrun_forward_off(moqtrun_sub_param(m, MOQCTL_PARAM_FORWARD));
  s->delivery_timeout     = moqtrun_param_vi(dt);
  s->has_delivery_timeout = dt != 0;
}

/* Opens slot s on t for peer_idx under alias, its state taken from
 * SUBSCRIBE m (0 for a silent re-attach: every draft default). */
static void moqtrun_sub_open(
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    usz                        peer_idx,
    u64                        alias,
    const moqctl_subscribe*    m) {
  s->session_idx = peer_idx;
  s->track_alias = alias;
  s->active      = 1;
  s->request_id  = m ? m->request_id : 0;
  moqtrun_sub_scalars(s, m);
  moqtrun_sub_filter(s, t, moqtrun_sub_param(m, MOQCTL_PARAM_LOCATION_FILTER));
}

/* 1 iff Objects go to s: Established and not FORWARD 0 (10.2.17). */
static int moqtrun_sub_forwards(const wired_moqtrun_sub* s) {
  return s->active && !s->forward_off;
}

static void moqtrun_reattach_one_sub(wired_moqtrun_track* track, usz i) {
  wired_moqtrun_sub* slot = moqtrun_sub_slot(track);
  if (!slot) return;
  moqtrun_sub_open(slot, track, i, moqtrun_next_alias(track), 0);
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
    moqtrun_key          k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (moqtrun_reattach_wanted(hub, track, i, pub_idx, k))
      moqtrun_reattach_one_sub(track, i);
}

static int moqtrun_encode_subscribe_ok(
    wired_mspan buf, usz* off, const void* m) {
  return moqctl_subscribe_ok_encode(buf, off, m);
}

/* SUBSCRIBE_OK with alias; LARGEST_OBJECT once t has published Objects
 * (MUST, draft 10.2.16). */
static void moqtrun_queue_subscribe_ok(
    wired_moqtrun_peer* p, const wired_moqtrun_track* t, u64 alias) {
  u8                  msg[WIRED_MOQTRUN_CTL_REPLY_MAX];
  moqctl_subscribe_ok ok  = {0};
  ok.track_alias          = alias;
  ok.params.items[0].type = MOQCTL_PARAM_LARGEST_OBJECT;
  ok.params.items[0].enc  = MOQCTL_PENC_LOCATION;
  ok.params.items[0].loc  = t->largest;
  ok.params.n             = t->has_largest ? 1 : 0;
  usz n                   = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_SUBSCRIBE_OK,
      moqtrun_encode_subscribe_ok, &ok);
  moqtrun_queue_reply(p, wired_span_of(msg, n));
}

/* Records slot (peer_idx, a fresh alias) against track and replies
 * SUBSCRIBE_OK with that alias. */
static void moqtrun_accept_subscribe(
    wired_moqtrun_peer*     p,
    wired_moqtrun_track*    track,
    wired_moqtrun_sub*      slot,
    usz                     peer_idx,
    const moqctl_subscribe* m) {
  moqtrun_sub_open(slot, track, peer_idx, moqtrun_next_alias(track), m);
  moqtrun_queue_subscribe_ok(p, track, slot->track_alias);
}

/* A peer's first SUBSCRIBE for the hub's blob: one io.send_uni with the
 * whole framed bytes, and only an accepted send records the subscription
 * (a refused one answers REQUEST_ERROR, so the peer's next SUBSCRIBE tries
 * again). Unlike a peer track's per-subscriber alias, SUBSCRIBE_OK carries
 * the blob's own alias -- the one its framed header has -- so the
 * subscriber can bind the stream to this subscription. */
/* Sends the blob to slot's peer p unless FORWARD 0 holds it back; 0 when
 * the send is refused. */
static int moqtrun_blob_deliver(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const wired_moqtrun_sub* slot) {
  if (!moqtrun_sub_forwards(slot)) return 1;
  if (hub->io.send_uni(p->wt, hub->blob_wire) >= 0) return 1;
  hub->stat_open_drop++;
  return 0;
}

static void moqtrun_blob_send_first(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m) {
  wired_moqtrun_sub* slot = moqtrun_sub_slot(&hub->blob_track);
  if (!slot) {
    moqtrun_send_request_error(p, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  moqtrun_sub_open(
      slot, &hub->blob_track, peer_idx, hub->blob_track.own_alias, m);
  if (!moqtrun_blob_deliver(hub, p, slot)) {
    slot->active = 0;
    moqtrun_send_request_error(p, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  moqtrun_queue_subscribe_ok(p, &hub->blob_track, slot->track_alias);
}

/* SUBSCRIBE for the hub's own blob track: a peer already holding a
 * subscription is answered SUBSCRIBE_OK again (its copy is on the way or
 * delivered -- never sent twice), anyone else gets the blob now. */
static void moqtrun_subscribe_blob(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m) {
  wired_moqtrun_sub* held =
      moqtrun_track_sub_of_peer(&hub->blob_track, peer_idx);
  if (held) {
    moqtrun_queue_subscribe_ok(p, &hub->blob_track, held->track_alias);
    return;
  }
  moqtrun_blob_send_first(hub, p, peer_idx, m);
}

/* SUBSCRIBE on a found peer track: a peer already holding a subscription
 * is answered SUBSCRIBE_OK again with the alias it holds (the client
 * resends SUBSCRIBE until a chunk arrives, and an idle track never sends
 * one -- each resend must not consume another slot), anyone else gets a
 * fresh slot, or DOES_NOT_EXIST once the table is full. */
static void moqtrun_subscribe_peer_track(
    wired_moqtrun_peer*     p,
    wired_moqtrun_track*    track,
    usz                     peer_idx,
    moqtrun_key             k,
    const moqctl_subscribe* m) {
  wired_moqtrun_sub* held = moqtrun_track_sub_of_peer(track, peer_idx);
  if (held) {
    moqtrun_queue_subscribe_ok(p, track, held->track_alias);
    return;
  }
  wired_moqtrun_sub* slot = moqtrun_sub_slot(track);
  if (!slot) {
    moqtrun_send_request_error(p, MOQCTL_ERR_DOES_NOT_EXIST);
    return;
  }
  moqtrun_accept_subscribe(p, track, slot, peer_idx, m);
  moqtrun_note_sub_name(p, k);
}

/* draft SS10.6 SUBSCRIBE for a peer-published track: find it and reply
 * SUBSCRIBE_OK with an assigned Track Alias, else DOES_NOT_EXIST. */
static void moqtrun_route_peer_subscribe(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m) {
  u8                   ns_buf[WIRED_MOQTRUN_MAX_NS];
  moqtrun_key          k     = moqtrun_key_of(&m->name, ns_buf);
  wired_moqtrun_track* track = moqtrun_find_published_track(hub, k);
  if (!track) {
    moqtrun_send_request_error(p, MOQCTL_ERR_DOES_NOT_EXIST);
    return;
  }
  moqtrun_subscribe_peer_track(p, track, peer_idx, k, m);
}

static void moqtrun_subscribe_live(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m);

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
    moqtrun_subscribe_blob(hub, p, peer_idx, m);
    return;
  }
  if (moqtrun_track_name_matches(&hub->live.track, m->name.name)) {
    moqtrun_subscribe_live(hub, p, peer_idx, m);
    return;
  }
  moqtrun_route_peer_subscribe(hub, p, peer_idx, m);
}

/* First AUTHORIZATION TOKEN parameter (draft SS10.2.2) of a message, or
 * 0 when it carries none. */
static const moqctl_token* moqtrun_auth_token_of(const moqctl_params* params) {
  const moqctl_param* t =
      moqctl_params_find(params, MOQCTL_PARAM_AUTHORIZATION_TOKEN);
  return t ? &t->token : 0;
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

/* A message with no request to refuse: consumed by its Length, no reply. */
static void moqtrun_dispatch_skip(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)hub;
  (void)p;
  (void)peer_idx;
  (void)body;
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
    /* draft SS10 known non-request messages this hub does not implement:
     * nothing carries a Request ID to answer, so they are skipped. */
    {0x8, moqtrun_dispatch_skip},  /* NAMESPACE */
    {0xE, moqtrun_dispatch_skip},  /* NAMESPACE_DONE */
    {0xF, moqtrun_dispatch_skip},  /* PUBLISH_SKIPPED */
    {0x18, moqtrun_dispatch_skip}, /* FETCH_OK */
};
#define MOQTRUN_CTL_TABLE_N \
  (sizeof(moqtrun_ctl_table) / sizeof(moqtrun_ctl_table[0]))

static moqtrun_ctl_fn moqtrun_ctl_lookup(u64 type) {
  for (usz i = 0; i < MOQTRUN_CTL_TABLE_N; i++)
    if (moqtrun_ctl_table[i].type == type) return moqtrun_ctl_table[i].fn;
  return moqtrun_dispatch_not_supported;
}

/* Closes p's session with code. Every later byte of p's control stream
 * is discarded (ctl_asm.skip never runs out). An io table without
 * close_session skips the message by its Length instead and keeps the
 * stream alive. */
static void moqtrun_close_with(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u32 code) {
  if (!hub->io.close_session) return;
  hub->io.close_session(p->wt, code, wired_span_of(0, 0));
  p->ctl_asm.at   = p->ctl_asm.n;
  p->ctl_asm.skip = (usz)-1;
}

/* draft SS10: an unknown message type MUST close the session; SS3.5
 * PROTOCOL_VIOLATION is the code. */
static void moqtrun_dispatch_close(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)peer_idx;
  (void)body;
  moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
}

/* A message longer than WIRED_MOQTRUN_CTL_MSG_MAX: the peer broke no
 * rule, the limit is ours, so SS3.5 INTERNAL_ERROR is the code. */
static void moqtrun_dispatch_over_cap(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)peer_idx;
  (void)body;
  moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_INTERNAL_ERROR);
}

/* moqtrun_asm_pop's result for a message over the cap. */
#define MOQTRUN_ASM_OVER_CAP (-100)

static moqtrun_ctl_fn moqtrun_ctl_route(int peek, u64 type) {
  if (peek == MOQCTL_UNKNOWN_TYPE) return moqtrun_dispatch_close;
  if (peek == MOQTRUN_ASM_OVER_CAP) return moqtrun_dispatch_over_cap;
  return moqtrun_ctl_lookup(type);
}

/* ===================== control-stream reassembly ===================== */

static void moqtrun_span_drop(wired_span* s, usz d) {
  s->p += d;
  s->n -= d;
}

/* Moves a's unread tail to the front, then appends as much of *data as
 * fits -- after discarding the bytes of an over-cap message still owed
 * (a->skip) -- and advances *data past everything consumed. */
static void moqtrun_asm_push(wired_moqtrun_ctl_asm* a, wired_span* data) {
  usz drop = (usz)u64_min(a->skip, data->n);
  a->skip -= drop;
  moqtrun_span_drop(data, drop);
  usz keep = a->n - a->at;
  bytes_memcpy(a->buf, a->buf + a->at, keep); /* forward copy: dst < src */
  usz take = (usz)u64_min(sizeof a->buf - keep, data->n);
  bytes_memcpy(a->buf + keep, data->p, take);
  a->n  = keep + take;
  a->at = 0;
  moqtrun_span_drop(data, take);
}

/* 1 iff rest starts with a complete header whose Length exceeds the cap;
 * *total is then the whole message's size. */
static int moqtrun_asm_over_cap(wired_span rest, usz* total) {
  usz at = 0;
  u64 type;
  u16 len;
  if (moqctl_peek_header(rest, &at, &type, &len) != MOQCTL_OK) return 0;
  *total = at + len;
  return len > WIRED_MOQTRUN_CTL_MSG_MAX;
}

/* Next complete message held in a (moqctl_peek_type's result, *body a view
 * into a->buf valid until the next push), or MOQCTL_INSUFFICIENT when more
 * bytes are needed. A message whose Length exceeds
 * WIRED_MOQTRUN_CTL_MSG_MAX is consumed by its Length, now and across
 * later deliveries (a->skip), and reported as MOQTRUN_ASM_OVER_CAP
 * (moqtrun_dispatch_over_cap). */
static int moqtrun_asm_pop(
    wired_moqtrun_ctl_asm* a, u64* type, wired_span* body) {
  if (a->skip) return MOQCTL_INSUFFICIENT; /* rest of a held message */
  wired_span rest  = wired_span_of(a->buf + a->at, a->n - a->at);
  usz        total = 0;
  if (moqtrun_asm_over_cap(rest, &total)) {
    usz held = (usz)u64_min(total, rest.n);
    a->at += held;
    a->skip = total - held;
    return MOQTRUN_ASM_OVER_CAP;
  }
  usz off = 0;
  int r   = moqctl_peek_type(rest, &off, type, body);
  a->at += off;
  return r;
}

/* Routes every complete message p->ctl_asm holds. */
static void moqtrun_ctl_drain(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx) {
  u64        type = 0;
  wired_span body = {0, 0};
  int        r;
  while ((r = moqtrun_asm_pop(&p->ctl_asm, &type, &body)) !=
         MOQCTL_INSUFFICIENT)
    moqtrun_ctl_route(r, type)(hub, p, peer_idx, body);
}

/* Dispatches every complete control message found in data (a request
 * stream carries exactly one; the shared control stream may carry more
 * than one per call), prefixed by the incomplete tail the previous call
 * left in p->ctl_asm -- a message may arrive split across calls. peer_idx is
 * passed through for handlers that need to record which session a subscription
 * belongs to. Every handler queues its reply (moqtrun_queue_reply) rather than
 * sending it immediately.
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
  moqtrun_flush_replies(&hub->io, p);
  do {
    moqtrun_asm_push(&p->ctl_asm, &data);
    moqtrun_ctl_drain(hub, p, peer_idx);
  } while (data.n > 0);
  moqtrun_flush_replies(&hub->io, p);
}

/* ===================== hub-owned blob track ===================== */

static void moqtrun_subgroup_scan(
    wired_span wire, wired_moqtrun_track* t, moqdata_objseq* seq, u64* group);

usz wired_moqt_publish_blob(
    wired_moqt_hub* hub,
    wired_span      name,
    u64             track_alias,
    wired_span      blob,
    wired_mspan     wire) {
  usz n = moqdata_blob_build(wire, track_alias, blob);
  if (n == 0) return 0;
  moqtrun_track_claim(
      hub, &hub->blob_track, moqtrun_key_name(name), track_alias);
  hub->blob_wire = wired_span_of(wire.p, n);
  moqdata_objseq seq;
  u64            group;
  moqtrun_subgroup_scan(hub->blob_wire, &hub->blob_track, &seq, &group);
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
  moqtrun_track_claim(
      hub, &hub->live.track, moqtrun_key_name(name), track_alias);
  hub->live.frags       = frags;
  hub->live.n_frags     = n_frags;
  hub->live.t0_ms       = now_ms;
  hub->live.group_ms    = group_ms;
  hub->live.last_now_ms = now_ms;
  moqtrun_track_note(&hub->live.track, 0, 0); /* Group 0 starts at t0 */
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
  if (!moqtrun_sub_forwards(&hub->live.track.subs[i])) return;
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
  moqtrun_track_note(&hub->live.track, g, 0);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    moqtrun_live_serve_sub(hub, i, g);
}

/* Records slot for peer_idx, replies SUBSCRIBE_OK with the live track's
 * own alias, and sends the Group current at the last tick at once (its
 * fragment starts with a keyframe). */
static void moqtrun_live_attach(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    wired_moqtrun_sub*      slot,
    usz                     peer_idx,
    const moqctl_subscribe* m) {
  usz i = (usz)(slot - hub->live.track.subs);
  moqtrun_sub_open(
      slot, &hub->live.track, peer_idx, hub->live.track.own_alias, m);
  hub->live.sent_any[i] = 0;
  moqtrun_queue_subscribe_ok(p, &hub->live.track, slot->track_alias);
  if (moqtrun_sub_forwards(slot))
    moqtrun_live_send_one(
        hub, i, moqtrun_live_group_at(&hub->live, hub->live.last_now_ms));
}

/* SUBSCRIBE for the live track: a peer already holding a subscription is
 * answered SUBSCRIBE_OK again (nothing re-sent), anyone else is attached
 * and served the current Group. */
static void moqtrun_subscribe_live(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m) {
  wired_moqtrun_track* t    = &hub->live.track;
  wired_moqtrun_sub*   held = moqtrun_track_sub_of_peer(t, peer_idx);
  if (held) {
    moqtrun_queue_subscribe_ok(p, t, held->track_alias);
    return;
  }
  wired_moqtrun_sub* slot = moqtrun_sub_slot(t);
  if (!slot) {
    moqtrun_send_request_error(p, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  moqtrun_live_attach(hub, p, slot, peer_idx, m);
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
    if (moqtrun_sub_forwards(&track->subs[i]))
      moqtrun_relay_to_one(hub, &track->subs[i], wire);
}

/* --- relay map: one entry per in-flight publisher stream (moqtrun.h's
 * wired_moqtrun_relay doc -- keyed by the PUBLISHER's stream id so several
 * of one track's streams can be forwarded concurrently). --- */

static usz moqtrun_decode_object_loop(
    wired_span           data,
    usz*                 off,
    moqdata_objseq*      seq,
    u64                  group,
    wired_moqtrun_track* t);

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
    if (moqtrun_sub_forwards(&track->subs[i]))
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
 * dropped round must never end mid-Object. Decoding continues the
 * stream's own Object sequence (relay->seq, set from its SUBGROUP_HEADER
 * by moqtrun_relay_start), so each Object's ID counts toward the track's
 * Largest. */
static wired_span moqtrun_relay_normalize(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           data) {
  usz total = relay->frag_len + data.n;
  usz off   = 0;
  bytes_memcpy(hub->relay_scratch, relay->frag, relay->frag_len);
  bytes_memcpy(hub->relay_scratch + relay->frag_len, data.p, data.n);
  moqtrun_decode_object_loop(
      wired_span_of(hub->relay_scratch, total), &off, &relay->seq,
      relay->group_id, track);
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
  if (!moqtrel_append(rb, whole)) {
    hub->stat_rel_overflow++;
    return;
  }
  hub->stat_rel_in_bytes += whole.n;
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
  rb->bound_ms   = hub->live.last_now_ms;
  moqtrun_rel_take(hub, rb, head);
  relay->rel_idx = (i32)(rb - hub->rel_pool);
  hub->stat_rel_rings++;
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

/* Activates sub slot i's ring cursor at offset sent if its relay stream
 * opened (the stream already carries every byte before sent); the stall
 * clock anchors at now_ms. head moves up to sent: no cursor reads below
 * it, and a nonzero head ends moqtrel_awaits_sub's wait. */
static void moqtrun_rel_attach_sub(
    moqtrel_buf*               rb,
    const wired_moqtrun_track* track,
    const wired_moqtrun_relay* relay,
    usz                        i,
    u64                        sent,
    u64                        now_ms) {
  if (!moqtrun_sub_forwards(&track->subs[i]) || !relay->sub_stream_set[i])
    return;
  rb->subs[i].active     = 1;
  rb->subs[i].shed       = 0; /* a reused slot must not inherit these */
  rb->subs[i].fin_done   = 0;
  rb->subs[i].sent       = sent;
  rb->subs[i].last_ok_ms = now_ms;
  rb->head               = sent;
}

/* After the opening moqtrun_relay_open_all: record each subscriber stream
 * that actually opened as a ring cursor at tail (the opening round carried
 * every byte so far). A slot that failed to open, or subscribes later,
 * rides this ring only through moqtrun_rel_late_attach_all -- i.e. only
 * while the ring still holds the stream right after its header. */
static void moqtrun_rel_attach_subs(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay) {
  if (relay->rel_idx < 0) return;
  moqtrel_buf* rb = &hub->rel_pool[relay->rel_idx];
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    moqtrun_rel_attach_sub(
        rb, track, relay, i, rb->tail, hub->live.last_now_ms);
}

static void moqtrun_relay_open_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    wired_span           wire);

/* 1 while nothing past the SUBGROUP_HEADER was reclaimed (and a header
 * was saved): a late subscriber's stream can be the saved header followed
 * by the ring from offset hdr_len -- the whole stream, not a torn tail. */
static int moqtrun_rel_holds_start(
    const wired_moqtrun_relay* relay, const moqtrel_buf* rb) {
  return relay->hdr_len != 0 && rb->head <= relay->hdr_len;
}

/* 1 for an active sub slot with neither a relay stream nor a cursor on
 * this ring (it became active after the relay started). A shed or
 * FIN'd cursor stays active, so it is never re-opened here. */
static int moqtrun_rel_late_wanted(
    const wired_moqtrun_track* track,
    const wired_moqtrun_relay* relay,
    const moqtrel_buf*         rb,
    usz                        i) {
  return moqtrun_sub_forwards(&track->subs[i]) && !relay->sub_stream_set[i] &&
         !rb->subs[i].active;
}

/* A late subscriber on a ring that still holds the whole stream: open its
 * relay stream with the saved header and attach its cursor right after
 * it, so the normal drain sends every byte, then the FIN. An open failure
 * attaches nothing and retries on the next drain. */
static void moqtrun_rel_late_attach(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u64                  now_ms) {
  if (!moqtrun_rel_late_wanted(track, relay, rb, i)) return;
  moqtrun_relay_open_one(
      hub, &track->subs[i], relay, i,
      wired_span_of(relay->hdr, relay->hdr_len));
  moqtrun_rel_attach_sub(rb, track, relay, i, relay->hdr_len, now_ms);
}

/* Covers both ways a subscription turns active mid-stream (SUBSCRIBE, and
 * the silent re-attach): every drain looks for such slots. */
static void moqtrun_rel_late_attach_all(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    u64                  now_ms) {
  if (!moqtrun_rel_holds_start(relay, rb)) return;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    moqtrun_rel_late_attach(hub, track, relay, rb, i, now_ms);
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
 * only costs that peer a dangling stream. The relay's record of the
 * stream clears too (as the lossy shed does): should this entry later
 * fall back to the lossy continue, a round must never stream_send to the
 * reset stream -- the subscriber late-opens afresh instead. */
static void moqtrun_rel_shed(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i) {
  hub->io.stream_reset(wt, relay->sub_stream_id[i], 0);
  relay->sub_stream_set[i] = 0;
  rb->subs[i].shed         = 1;
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
  if (hub->io.stream_fin(wt, relay->sub_stream_id[i]) != 1) return;
  rb->subs[i].fin_done = 1;
  hub->stat_rel_fin_out++;
}

/* 1 when this round's last byte is the stream's last byte ever: the
 * send can carry the closing FIN itself. */
static int moqtrun_rel_round_fins(const moqtrel_buf* rb, usz i, usz n) {
  return rb->fin_seen && rb->subs[i].sent + n == rb->tail;
}

/* An accepted round: advance the cursor (restarting its stall clock) and
 * mark the FIN done when the round carried it. */
static void moqtrun_rel_round_ok(
    wired_moqt_hub* hub,
    moqtrel_buf*    rb,
    usz             i,
    usz             n,
    int             fin_flag,
    u64             now_ms) {
  moqtrel_note_sent(rb, (u32)i, n, now_ms);
  if (!fin_flag) return;
  rb->subs[i].fin_done = 1;
  hub->stat_rel_fin_out++;
}

/* 1 when session wt's remaining credit can carry an n-byte round and
 * still leave WIRED_MOQTREL_HEADROOM for the session's other (lossy)
 * traffic; a table without send_budget never constrains. */
static int moqtrun_rel_budget_ok(
    wired_moqt_hub* hub, wired_wt_session* wt, usz n) {
  if (!hub->io.send_budget) return 1;
  return hub->io.send_budget(wt) >= n + WIRED_MOQTREL_HEADROOM;
}

/* Budget gate for one round: 0 lets it proceed, 1 defers it whole,
 * counted on stat_rel_wait. The cursor AND its stall clock stay put: a
 * deferral is not progress, so a peer whose credit never recovers trips
 * moqtrel_stalled after WIRED_MOQTREL_STALL_MS and is shed exactly like
 * one whose sends are refused -- it must not pin the ring (and the
 * publisher hold) forever. A healthy line recovers credit within an RTT,
 * far under the stall clock. */
static int moqtrun_rel_budget_wait(
    wired_moqt_hub* hub, wired_wt_session* wt, usz n) {
  if (moqtrun_rel_budget_ok(hub, wt, n)) return 0;
  hub->stat_rel_wait++;
  return 1;
}

/* The send itself: the FIN rides the stream's last byte; an accepted
 * round advances the cursor, a refusal changes nothing. */
static void moqtrun_rel_send_span(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    wired_span           span,
    u64                  now_ms) {
  int fin_flag = moqtrun_rel_round_fins(rb, i, span.n);
  if (hub->io.stream_send(wt, relay->sub_stream_id[i], span, fin_flag) != 1) {
    hub->stat_rel_refused++;
    return;
  }
  hub->stat_rel_sent++;
  moqtrun_rel_round_ok(hub, rb, i, span.n, fin_flag, now_ms);
}

/* One send round for cursor i: the ring's next contiguous span, deferred
 * whole while the session's credit cannot spare it, the FIN riding the
 * last one. A refusal or deferral changes nothing -- the same span
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
  if (moqtrun_rel_budget_wait(hub, wt, span.n)) return;
  moqtrun_rel_send_span(hub, wt, relay, rb, i, span, now_ms);
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

/* Returns the ring to the pool. A still-applied hold is released first --
 * an all-shed ring can finish while the publisher still sends, and its
 * receive credit must not stay frozen forever. */
static void moqtrun_rel_return_ring(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, moqtrel_buf* rb) {
  if (rb->held) hub->io.stream_hold(rb->pub, rb->pub_stream, 0);
  rb->in_use     = 0;
  relay->rel_idx = -1;
}

/* Every cursor delivered or given up: the ring returns to the pool. The
 * relay entry frees only once the publisher's FIN was seen; before that
 * it stays bound (rel_idx -1: the lossy continue, which sends nothing
 * with no live subscribers), so the publisher's later deliveries on the
 * same stream keep matching it. Freeing early would re-classify those
 * deliveries as a fresh stream head -- mid-Object bytes decoded as a
 * SUBGROUP_HEADER can resolve to another track's alias and relay garbage
 * to its subscribers. */
static void moqtrun_rel_maybe_done(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, moqtrel_buf* rb) {
  if (!moqtrel_all_done(rb)) return;
  int fin_seen = rb->fin_seen;
  hub->stat_rel_early_return += (u64)!fin_seen;
  moqtrun_rel_return_ring(hub, relay, rb);
  if (fin_seen) relay->in_use = 0;
}

/* One full drain pass over a ring: attach late subscribers, a round per
 * open cursor, reclaim what every live cursor has passed, then the two
 * closing decisions (release the hold once enough drained, return
 * everything once every cursor is delivered or given up). A ring no
 * cursor ever joined skips all three while it awaits a first subscriber
 * (moqtrel_awaits_sub): reclaiming would discard the stream's start.
 * ponytail: a subscriber-less ring may hold its publisher up to
 * WIRED_MOQTREL_STALL_MS; a separate wait budget if that proves long. */
static void moqtrun_rel_drain_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    u64                  now_ms) {
  moqtrun_rel_late_attach_all(hub, track, relay, rb, now_ms);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    moqtrun_rel_drain_sub(hub, track, relay, rb, i, now_ms);
  if (moqtrel_awaits_sub(rb, now_ms)) return;
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
  hub->stat_rel_hold++;
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
  if (fin) {
    rb->fin_seen = 1;
    hub->stat_rel_fin_in++;
  }
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
  wired_span whole = moqtrun_relay_normalize(hub, track, relay, wire);
  if (relay->rel_idx >= 0) {
    moqtrun_rel_continue(hub, track, relay, whole, fin);
    return;
  }
  moqtrun_relay_continue_lossy(hub, track, relay, whole, fin);
}

/* Opens sub slot i's relay stream carrying wire as its first round and
 * records the id for later rounds. An open failure (no free send slot on
 * that connection) leaves the slot unset: a lossy relay late-opens it on
 * a later round (moqtrun_relay_late_open), a ring-backed one retries on
 * the next drain while the ring still holds the stream's start
 * (moqtrun_rel_late_attach_all), else it gets nothing. */
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
    if (moqtrun_sub_forwards(&track->subs[i]))
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
  moqtrun_subgroup_scan(
      wired_span_of(wire.p, whole_end), 0, &relay->seq, &relay->group_id);
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
    wired_span           data,
    usz*                 off,
    moqdata_objseq*      seq,
    u64                  group,
    wired_moqtrun_track* t) {
  usz n = 0;
  while (*off < data.n) {
    moqdata_obj obj;
    if (moqdata_obj_take(data, off, seq, &obj) != MOQDATA_OK) break;
    moqtrun_track_note(t, group, obj.object_id);
    n++;
  }
  return n;
}

/* SUBGROUP_HEADER + every whole Object of wire, noting each on t (0: no
 * track); *seq / *group receive the stream's state after the last whole
 * Object, for a relay's header-less later deliveries. */
static void moqtrun_subgroup_scan(
    wired_span wire, wired_moqtrun_track* t, moqdata_objseq* seq, u64* group) {
  usz            off = 0;
  moqdata_subhdr hdr;
  if (moqdata_subhdr_take(wire, &off, &hdr) != MOQDATA_OK) return;
  *seq   = moqdata_objseq_of(hdr.type);
  *group = hdr.group_id;
  moqtrun_decode_object_loop(wire, &off, seq, hdr.group_id, t);
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
  wired_moqtrun_track* t   = moqtrun_track_by_alias(p, hdr.track_alias);
  moqdata_objseq       seq = moqdata_objseq_of(hdr.type);
  if (moqtrun_fresh_nothing_due(
          moqtrun_decode_object_loop(data, &off, &seq, hdr.group_id, t), fin))
    return 0;
  *whole_end = off;
  return t;
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
  wired_moqtrun_track* t = moqtrun_track_by_alias(p, obj.track_alias);
  moqtrun_track_note(t, obj.group_id, obj.object_id);
  return t;
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
    if (moqtrun_sub_forwards(&track->subs[i]))
      moqtrun_dg_to_one(hub, &track->subs[i], data);
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
  /* The leaver's own rings return now (moqtrun_rel_drop_ring's doc); its
   * relay entries stay untouched so a later re-claim can still reset the
   * subscriber streams they record (moqtrun_track_reset_stale_relays). */
  moqtrun_peer_drop_rings(hub, p);
  p->in_use = 0;
}
