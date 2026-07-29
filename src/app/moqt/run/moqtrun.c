#include "app/moqt/run/moqtrun.h"

#include "app/moqt/ctl/moqctl.h"
#include "app/moqt/data/moqdata.h"
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

void wired_moqt_init(wired_moqt_hub* hub, wired_moqt_io io) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) hub->peers[i].in_use = 0;
  hub->io = io;
}

/* SS10 common envelope (Type vi64 + 16-bit Length + Body): every control
 * message this hub sends goes through this one encoder, so the Length
 * backpatch lives in exactly one place. Returns bytes written, or 0 if the
 * body encoder failed (buf too small). */
typedef int (*moqtrun_body_encode_fn)(quic_mspan, usz*, const void*);

static usz moqtrun_envelope_put(
    quic_mspan buf, u64 type, moqtrun_body_encode_fn body_fn, const void* msg) {
  usz eoff = 0;
  if (!quic_moqvi_put(buf, &eoff, type)) return 0;
  usz len_at = eoff;
  eoff += 2;
  usz body_at = eoff;
  if (!body_fn(buf, &eoff, msg)) return 0;
  buf.p[len_at]     = (u8)((eoff - body_at) >> 8);
  buf.p[len_at + 1] = (u8)(eoff - body_at);
  return eoff;
}

static int moqtrun_encode_setup(quic_mspan buf, usz* off, const void* m) {
  return quic_moqctl_setup_encode(buf, off, m);
}

/* draft 3.3: the control stream's first message is the endpoint's own
 * SETUP, no Setup Options (this subset negotiates nothing on the wire).
 * io->open_bidi_stream is responsible for prefixing the WebTransport
 * stream signal (draft-ietf-webtrans-http3-15 4.2) ahead of these bytes --
 * this layer stays session-opaque (wired_wt_session is never dereferenced
 * here, only passed through) so it stays testable without the QUIC/TLS
 * stack; see moqtrun.h's io table doc. */
static u64 moqtrun_send_setup(wired_moqt_io* io, wired_wt_session* s, u8* buf) {
  quic_moqctl_setup setup = {0};
  usz               n     = moqtrun_envelope_put(
      quic_mspan_of(buf, WIRED_MOQTRUN_CTL_SEND_BUF), QUIC_MOQCTL_T_SETUP,
      moqtrun_encode_setup, &setup);
  i64 sid = io->open_bidi_stream(s, quic_span_of(buf, n));
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
  p->send_lens[0]    = 0;
  p->send_lens[1]    = 0;
  p->armed_idx       = 0;
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    p->tracks[t].in_use = 0;
  quic_moqsess_init(&p->sess);
  p->control_stream_id = moqtrun_send_setup(&hub->io, s, p->send_bufs[0]);
  quic_moqsess_step(&p->sess, QUIC_MOQSESS_EV_SENT_SETUP);
}

void wired_moqt_on_session(
    void* app_ctx, wired_wt_session* s, quic_span path, quic_span protocol) {
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
  return t == QUIC_MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT ||
         t == QUIC_MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT;
}

static int moqtrun_param_is_nonzero_timeout(const quic_moqctl_param* item) {
  return moqtrun_is_timeout_type(item->type) && item->vi != 0;
}

static int moqtrun_has_timeout_param(const quic_moqctl_params* params) {
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
static void moqtrun_queue_reply(wired_moqtrun_peer* p, quic_span msg) {
  int pending_idx = p->armed_idx ^ 1;
  if (p->send_lens[pending_idx] + msg.n > WIRED_MOQTRUN_CTL_SEND_BUF) return;
  quic_memcpy(
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
      quic_span_of(p->send_bufs[pending_idx], p->send_lens[pending_idx]), 0);
  if (r <= 0) return;
  p->send_lens[p->armed_idx] = 0; /* old armed slot: now safe to reuse */
  p->armed_idx               = pending_idx;
}

static int moqtrun_encode_request_error(
    quic_mspan buf, usz* off, const void* m) {
  return quic_moqctl_request_error_encode(buf, off, m);
}

static void moqtrun_send_request_error(wired_moqtrun_peer* p, u64 code) {
  u8                        msg[WIRED_MOQTRUN_CTL_MSG_MAX];
  quic_moqctl_request_error e = {0};
  e.error_code                = code;
  usz n                       = moqtrun_envelope_put(
      quic_mspan_of(msg, sizeof msg), QUIC_MOQCTL_T_REQUEST_ERROR,
      moqtrun_encode_request_error, &e);
  moqtrun_queue_reply(p, quic_span_of(msg, n));
}

/* Copies name into t->name (Track Name = participant id, or
 * "<participant id>/audio"), truncated to WIRED_MOQTRUN_MAX_NAME (room ids
 * are short; a real deployment would reject an oversized one instead --
 * ponytail: no such input in this subset's usage). */
static void moqtrun_record_track_name(wired_moqtrun_track* t, quic_span name) {
  usz n = name.n < WIRED_MOQTRUN_MAX_NAME ? name.n : WIRED_MOQTRUN_MAX_NAME;
  quic_memcpy(t->name, name.p, n);
  t->name_len = n;
}

static int moqtrun_bytes_eq(const u8* a, const u8* b, usz n) {
  for (usz i = 0; i < n; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

static int moqtrun_track_name_matches(
    const wired_moqtrun_track* t, quic_span name) {
  return t->in_use && t->name_len == name.n &&
         moqtrun_bytes_eq(t->name, name.p, name.n);
}

/* Finds p's own track slot already PUBLISHed under name, else 0. */
static wired_moqtrun_track* moqtrun_track_slot_for_name(
    wired_moqtrun_peer* p, quic_span name) {
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
    wired_moqtrun_peer* p, quic_span name) {
  wired_moqtrun_track* existing = moqtrun_track_slot_for_name(p, name);
  return existing ? existing : moqtrun_track_free_slot(p);
}

static int moqtrun_encode_request_ok(quic_mspan buf, usz* off, const void* m) {
  return quic_moqctl_request_ok_encode(buf, off, m);
}

/* Clears t's subscriber slots -- only needed the first time a fresh (not
 * re-PUBLISHed) slot is claimed. */
static void moqtrun_track_clear_subs(wired_moqtrun_track* t) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) t->subs[i].active = 0;
}

/* Claims slot t for a PUBLISH naming name/track_alias: clears subs only on
 * a fresh (not-yet-in_use) slot, so a re-PUBLISH under the same name keeps
 * its existing subscribers (matching the prior single-track hub's
 * overwrite behavior). */
static void moqtrun_track_claim(
    wired_moqtrun_track* t, quic_span name, u64 track_alias) {
  if (!t->in_use) moqtrun_track_clear_subs(t);
  t->in_use             = 1;
  t->own_alias          = track_alias;
  t->data_stream_id_set = 0; /* a (re-)PUBLISH always opens a fresh stream */
  moqtrun_record_track_name(t, name);
}

/* draft SS10.9 PUBLISH: accept a track into a free (or matching-name) slot
 * and reply REQUEST_OK; a third distinct track name (no free slot) gets
 * REQUEST_ERROR instead of silently overwriting an existing track. */
static void moqtrun_handle_publish(wired_moqtrun_peer* p, quic_span body) {
  usz                 off = 0;
  quic_moqctl_publish m;
  if (quic_moqctl_publish_take(body, &off, &m) != QUIC_MOQCTL_OK) return;
  wired_moqtrun_track* t = moqtrun_track_alloc_slot(p, m.name.name);
  if (!t) {
    moqtrun_send_request_error(p, QUIC_MOQCTL_ERR_NOT_SUPPORTED);
    return;
  }
  moqtrun_track_claim(t, m.name.name, m.track_alias);
  u8                     msg[WIRED_MOQTRUN_CTL_MSG_MAX];
  quic_moqctl_request_ok ok = {0};
  usz                    n  = moqtrun_envelope_put(
      quic_mspan_of(msg, sizeof msg), QUIC_MOQCTL_T_REQUEST_OK,
      moqtrun_encode_request_ok, &ok);
  moqtrun_queue_reply(p, quic_span_of(msg, n));
}

/* p's matching track slot if p is a connected peer, else 0 -- guards the
 * in_use check ahead of the name scan so the caller's loop body is one
 * unconditional call. */
static wired_moqtrun_track* moqtrun_peer_track_for_name(
    wired_moqtrun_peer* p, quic_span name) {
  return p->in_use ? moqtrun_track_slot_for_name(p, name) : 0;
}

/* Finds the track whose own PUBLISHed Track Name equals the requested
 * SUBSCRIBE's Track Name (room membership keys on participant id/suffix,
 * namespace is hub-fixed and not compared), across every connected peer. */
static wired_moqtrun_track* moqtrun_find_published_track(
    wired_moqt_hub* hub, const quic_moqctl_ftn* name) {
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

static int moqtrun_encode_subscribe_ok(
    quic_mspan buf, usz* off, const void* m) {
  return quic_moqctl_subscribe_ok_encode(buf, off, m);
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
  u8                       msg[WIRED_MOQTRUN_CTL_MSG_MAX];
  quic_moqctl_subscribe_ok ok = {0};
  ok.track_alias              = slot->track_alias;
  usz n                       = moqtrun_envelope_put(
      quic_mspan_of(msg, sizeof msg), QUIC_MOQCTL_T_SUBSCRIBE_OK,
      moqtrun_encode_subscribe_ok, &ok);
  moqtrun_queue_reply(p, quic_span_of(msg, n));
}

/* draft SS10.6 SUBSCRIBE: find the matching published track and reply
 * SUBSCRIBE_OK with a freshly assigned Track Alias, else DOES_NOT_EXIST.
 * Caller has already rejected timeout parameters. */
static void moqtrun_route_subscribe(
    wired_moqt_hub*              hub,
    wired_moqtrun_peer*          p,
    usz                          peer_idx,
    const quic_moqctl_subscribe* m) {
  wired_moqtrun_track* track = moqtrun_find_published_track(hub, &m->name);
  wired_moqtrun_sub*   slot  = track ? moqtrun_sub_slot(track) : 0;
  if (!slot) {
    moqtrun_send_request_error(p, QUIC_MOQCTL_ERR_DOES_NOT_EXIST);
    return;
  }
  moqtrun_accept_subscribe(p, track, slot, peer_idx);
}

/* draft SS10.6 SUBSCRIBE: reject non-zero delivery-timeout parameters,
 * else delegate matching + response to moqtrun_route_subscribe. */
static void moqtrun_handle_subscribe(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, quic_span body) {
  usz                   off = 0;
  quic_moqctl_subscribe m;
  if (quic_moqctl_subscribe_take(body, &off, &m) != QUIC_MOQCTL_OK) return;
  if (moqtrun_has_timeout_param(&m.params)) {
    moqtrun_send_request_error(p, QUIC_MOQCTL_ERR_NOT_SUPPORTED);
    return;
  }
  moqtrun_route_subscribe(hub, p, peer_idx, &m);
}

static void moqtrun_handle_not_supported(wired_moqtrun_peer* p) {
  moqtrun_send_request_error(p, QUIC_MOQCTL_ERR_NOT_SUPPORTED);
}

/* draft 5.1: a GOAWAY arriving on a request stream (not the control
 * stream) is informational in this subset -- accepted without closing the
 * session. The 2nd-GOAWAY-on-one-stream violation is a sess-layer
 * concern the caller already routes through quic_moqsess_step; nothing
 * further to do here since this hub sends no GOAWAY of its own on a
 * request stream. */
static void moqtrun_handle_request_goaway(void) {}

typedef void (*moqtrun_ctl_fn)(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, quic_span body);

static void moqtrun_dispatch_publish(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, quic_span body) {
  (void)hub;
  (void)peer_idx;
  moqtrun_handle_publish(p, body);
}

static void moqtrun_dispatch_subscribe(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, quic_span body) {
  moqtrun_handle_subscribe(hub, p, peer_idx, body);
}

static void moqtrun_dispatch_not_supported(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, quic_span body) {
  (void)hub;
  (void)peer_idx;
  (void)body;
  moqtrun_handle_not_supported(p);
}

static void moqtrun_dispatch_goaway(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, quic_span body) {
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
    {QUIC_MOQCTL_T_PUBLISH, moqtrun_dispatch_publish},
    {QUIC_MOQCTL_T_SUBSCRIBE, moqtrun_dispatch_subscribe},
    {QUIC_MOQCTL_T_GOAWAY, moqtrun_dispatch_goaway},
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
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, quic_span data) {
  usz off = 0;
  moqtrun_flush_replies(&hub->io, p);
  while (off < data.n) {
    u64       type = 0;
    quic_span body = {0, 0};
    int       r    = quic_moqctl_peek_type(data, &off, &type, &body);
    if (r != QUIC_MOQCTL_OK) break;
    moqtrun_ctl_lookup(type)(hub, p, peer_idx, body);
  }
  moqtrun_flush_replies(&hub->io, p);
}

/* ===================== data-stream (Object) relay ===================== */

/* Sends wire (a complete SUBGROUP_HEADER+Object stream, unmodified)
 * to one subscriber, whole, as exactly one fresh uni stream,
 * FIN'd on its only round -- io->send_uni is the one-shot
 * open+send+FIN primitive (a bare empty stream_send(..., fin=1) does NOT
 * work: wired_server_wt_stream_send never accepts an empty payload, since
 * a FIN needs a final non-empty slice to ride on). io->send_uni is
 * responsible for the WebTransport stream signal prefix, same as
 * moqtrun_send_setup. */
static void moqtrun_relay_to_one(
    wired_moqt_hub* hub, const wired_moqtrun_sub* sub, quic_span wire) {
  wired_moqtrun_peer* dst = &hub->peers[sub->session_idx];
  if (!dst->in_use) return;
  hub->io.send_uni(dst->wt, wire);
}

static void moqtrun_relay_object(
    wired_moqt_hub* hub, wired_moqtrun_track* track, quic_span wire) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (track->subs[i].active) moqtrun_relay_to_one(hub, &track->subs[i], wire);
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
 * (quic_moqdata_obj_take leaves *off unchanged on any non-OK result).
 * Returns the count of Objects decoded (0 if the very first one fails --
 * nothing to relay). A single-Object stream decodes identically to this
 * hub's former one-shot-Object path, this is that path's generalization to
 * N Objects on one stream. */
static usz moqtrun_decode_object_loop(
    quic_span data, usz* off, const quic_moqdata_subhdr* hdr) {
  quic_moqdata_objseq seq = quic_moqdata_objseq_of(hdr->type);
  usz                 n   = 0;
  while (*off < data.n) {
    quic_moqdata_obj obj;
    if (quic_moqdata_obj_take(data, off, &seq, &obj) != QUIC_MOQDATA_OK) break;
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

static int moqtrun_track_bound_to_stream(
    const wired_moqtrun_track* track, u64 stream_id) {
  return track->in_use && track->data_stream_id_set &&
         track->data_stream_id == stream_id;
}

/* p's track slot already bound to stream_id by an earlier
 * wired_moqt_on_stream_data call on this peer, else 0 -- see
 * wired_moqtrun_track's data_stream_id doc. */
static wired_moqtrun_track* moqtrun_track_by_stream_id(
    wired_moqtrun_peer* p, u64 stream_id) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    if (moqtrun_track_bound_to_stream(&p->tracks[t], stream_id))
      return &p->tracks[t];
  return 0;
}

/* Classifies a FRESH data stream's leading Stream Type varint and, for
 * SUBGROUP_HEADER, decodes the header + every following Object (moqtrun_
 * decode_object_loop), resolving the header's Track Alias to one of p's
 * (chat/audio) track slots -- else 0 (not a SUBGROUP stream, header
 * decode failure, zero Objects decoded, or an unknown Track Alias). On a
 * resolved track, remembers stream_id on it so later header-less calls on
 * the SAME stream_id skip straight to moqtrun_resolve_known_stream_track
 * instead of misreading Object bytes as a fresh header. */
/* SUBGROUP_HEADER + every following Object, for a stream already
 * confirmed to classify as SUBGROUP -- split out of moqtrun_resolve_fresh_
 * stream_track to keep that function's own branch count at the CCN gate. */
static wired_moqtrun_track* moqtrun_decode_fresh_subgroup(
    wired_moqtrun_peer* p, quic_span data) {
  usz                 off = 0;
  quic_moqdata_subhdr hdr;
  if (quic_moqdata_subhdr_take(data, &off, &hdr) != QUIC_MOQDATA_OK) return 0;
  if (moqtrun_decode_object_loop(data, &off, &hdr) == 0) return 0;
  return moqtrun_track_by_alias(p, hdr.track_alias);
}

static void moqtrun_bind_track_to_stream(
    wired_moqtrun_track* track, u64 stream_id) {
  track->data_stream_id     = stream_id;
  track->data_stream_id_set = 1;
}

static wired_moqtrun_track* moqtrun_resolve_fresh_stream_track(
    wired_moqtrun_peer* p, quic_span data, u64 stream_id) {
  usz classify_off = 0;
  int kind         = quic_moqdata_classify(data, &classify_off);
  if (kind != QUIC_MOQDATA_STREAM_SUBGROUP) return 0;
  wired_moqtrun_track* track = moqtrun_decode_fresh_subgroup(p, data);
  if (track) moqtrun_bind_track_to_stream(track, stream_id);
  return track;
}

/* Continues a data stream already bound to a track (moqtrun_track_by_
 * stream_id): unlike a fresh stream, `data` here carries NO
 * SUBGROUP_HEADER -- moqtVoiceClient.ts's sendOpusFrame writes the header
 * only on its first call, every later call on the same long-lived stream
 * appends bare Objects -- so decoding starts straight at offset 0. hdr.type
 * stays 0 (never a real SUBGROUP_HEADER Type): moqtrun_decode_object_loop
 * only reads hdr->type for its Properties bit, and every voice stream this
 * hub relays uses SUBGROUP_HEADER_TYPE (moqtClient.ts, Properties off), so
 * type 0's "no Properties" reading matches. Returns the track on at least
 * one decoded Object, else 0. */
static wired_moqtrun_track* moqtrun_resolve_known_stream_track(
    wired_moqtrun_track* track, quic_span data) {
  quic_moqdata_subhdr hdr = {0};
  usz                 off = 0;
  if (moqtrun_decode_object_loop(data, &off, &hdr) == 0) return 0;
  return track;
}

/* draft 3.4/11.4.2: relay a data stream's Objects verbatim to the
 * subscribers of the track its Track Alias names. A stream_id already
 * bound to a track (wired_moqtrun_track's own doc -- the audio track's
 * long-lived stream, appended to across many calls) skips classification
 * and header decoding entirely; any other stream_id is treated as fresh
 * and classified/header-decoded as usual. Padding streams (0x132B3E28),
 * any other classification, and an unknown Track Alias are discarded
 * here: classification-level session closes are the sess layer's job,
 * driven elsewhere from the same decoded quic_moqsess_event. */
static void moqtrun_dispatch_data_stream(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 stream_id, quic_span data) {
  wired_moqtrun_track* known = moqtrun_track_by_stream_id(p, stream_id);
  wired_moqtrun_track* track =
      known ? moqtrun_resolve_known_stream_track(known, data)
            : moqtrun_resolve_fresh_stream_track(p, data, stream_id);
  if (track) moqtrun_relay_object(hub, track, data);
}

/* ===================== public entry points ===================== */

void wired_moqt_on_stream_data(
    void*             app_ctx,
    wired_wt_session* s,
    u64               stream_id,
    quic_span         data,
    int               fin) {
  (void)fin;
  wired_moqt_hub*     hub = (wired_moqt_hub*)app_ctx;
  wired_moqtrun_peer* p   = moqtrun_find_by_wt(hub, s);
  if (!p) return;
  if (stream_id == p->control_stream_id) {
    usz peer_idx = (usz)(p - hub->peers);
    moqtrun_dispatch_ctl_stream(hub, p, peer_idx, data);
    return;
  }
  moqtrun_dispatch_data_stream(hub, p, stream_id, data);
}
