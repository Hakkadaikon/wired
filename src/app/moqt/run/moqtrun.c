#include "app/moqt/run/moqtrun.h"

#include "app/moqt/ctl/moqctl.h"
#include "app/moqt/data/moqdata.h"
#include "app/moqt/dgram/moqdg.h"
#include "app/moqt/fetch/moqfetch.h"
#include "app/moqt/kvp/moqkvp.h"
#include "app/moqt/ns/moqns.h"
#include "app/moqt/tstat/moqtstat.h"
#include "app/moqt/ver/moqver.h"
#include "app/moqt/vi/moqvi.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"
#include "common/bytes/util/num.h"

/* draft-ietf-moq-transport-19 hub relay. See moqtrun.h for the
 * design summary; each function here stays a thin dispatch over the
 * vi/kvp/ctl/data/sess domains, never reimplementing their codecs. */

/* draft-ietf-moq-transport-19 3.3.4 stream reset codes. */
#define MOQTRUN_RESET_INTERNAL_ERROR 0x0
#define MOQTRUN_RESET_CANCELLED 0x1
#define MOQTRUN_RESET_DELIVERY_TIMEOUT 0x2
#define MOQTRUN_RESET_GOING_AWAY 0x4
#define MOQTRUN_RESET_EXCESSIVE_LOAD 0x9

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

static void moqtrun_reqs_clear(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) hub->reqs[i].in_use = 0;
}

static void moqtrun_frag_pool_clear(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_FRAG_POOL; i++) hub->frag_owner[i] = 0;
}

static void moqtrun_fetch_arr_clear(wired_moqtrun_fetch* arr) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    arr[i].in_use = 0;
    arr[i].wt     = 0;
  }
}

static void moqtrun_fetches_clear(wired_moqt_hub* hub) {
  moqtrun_fetch_arr_clear(hub->fetches);
  moqtrun_fetch_arr_clear(hub->fetch_waits);
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
  hub->authorize_publish     = 0;
  hub->authorize_pub_ctx     = 0;
  hub->authorize_namespace   = 0;
  hub->authorize_ns_ctx      = 0;
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
  hub->stat_timeout_reset    = 0;
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
  moqtrun_reqs_clear(hub);
  moqtrun_frag_pool_clear(hub);
  moqcache_init(&hub->cache, 0, 0);
  hub->cache_tag_next = 0;
  moqtrun_fetches_clear(hub);
}

int wired_moqt_cache_attach(wired_moqt_hub* hub, u8* arena, usz size) {
  moqcache_init(&hub->cache, arena, size);
  return size != 0;
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

static i64 moqtrun_ctl_open_io(
    wired_moqt_io* io, wired_wt_session* s, int legacy, wired_span b) {
  return legacy ? io->open_bidi_stream(s, b) : io->open_uni_stream(s, b);
}

/* draft 3.3: the hub's control stream, its own SETUP as first bytes
 * (Setup Options: the hub's MAX_FILTER_RANGES / MAX_REQUEST_UPDATES
 * limits, 10.4). The draft-19 binding is a keep-open UNI stream whose
 * leading Stream Type varint (0x2F00, 3.4) IS the SETUP message's own
 * Type field -- the two are the same varint, not two (compare
 * FETCH_HEADER 11.4.4: one Type varint serves both the stream-type
 * table and the message layout); a legacy session keeps the pre-d17
 * single bidi the browser clients read, which carries no stream-type
 * varint at all. The io open ops prefix the WebTransport stream signal
 * (draft-ietf-webtrans-http3-15 4.2) -- this layer stays session-opaque,
 * testable without the QUIC/TLS stack. A refused open leaves ctl_opened
 * 0: moqtrun_ctl_retry tries again on a later tick, and nothing (GOAWAY
 * included) is sent until SETUP went out. SETUP rides send_bufs[0], the
 * armed slot (an open holds the same view/ACK contract as stream_send,
 * srvrun.h). */
/* MAX_FILTER_RANGES (0x06) / MAX_REQUEST_UPDATES (0x08) exist from
 * draft-19 10.4 on; draft-18 10.3.1 has neither, so a draft-18 SETUP
 * leaves them 0 -- moqctl_setup_put_num keeps a 0 option off the wire. */
static void moqtrun_setup_limits(moqctl_setup* s, int ver) {
  u32 caps = moqver_caps(ver);
  if (caps & MOQVER_CAP_RANGE_FILTERS)
    s->max_filter_ranges = WIRED_MOQTRUN_MAX_FILTER_RANGES;
  if (caps & MOQVER_CAP_MAX_REQUEST_UPDATES)
    s->max_request_updates = WIRED_MOQTRUN_MAX_REQ_UPDATES;
}

static void moqtrun_ctl_open(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  wired_mspan buf = wired_mspan_of(p->send_bufs[0], WIRED_MOQTRUN_CTL_SEND_BUF);
  moqctl_setup setup = {0};
  moqtrun_setup_limits(&setup, p->ver);
  usz off =
      moqtrun_envelope_put(buf, MOQCTL_T_SETUP, moqtrun_encode_setup, &setup);
  i64 sid = moqtrun_ctl_open_io(
      &hub->io, p->wt, p->legacy, wired_span_of(buf.p, off));
  if (sid < 0) return;
  p->control_stream_id = (u64)sid;
  p->ctl_opened        = 1;
  moqsess_step(&p->sess, MOQSESS_EV_SENT_SETUP);
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
    int                 legacy) {
  p->in_use          = 1;
  p->wt              = s;
  p->ver             = ver;
  p->legacy          = (u8)legacy;
  p->ctl_opened      = 0;
  p->request_id_next = 1; /* hub is the server: odd, 1-origin (draft SS10.2) */
  p->peer_rid_next   = 0; /* client Request IDs: even, 0-origin */
  p->join_seq        = hub->join_seq_next++;
  p->sub_names_n     = 0;
  p->sub_names_at    = 0;
  p->send_lens[0]    = 0;
  p->send_lens[1]    = 0;
  p->armed_idx       = 0;
  p->ctl_asm.n       = 0;
  p->ctl_asm.at      = 0;
  p->ctl_asm.skip    = 0;
  p->req             = 0;
  p->peer_ctl_set    = 0;
  p->peer_ctl_stream_id = 0;
  p->setup_recv         = 0;
  p->rx_sid             = 0;
  p->rx                 = 0;
  p->peer_ctl_asm.n     = 0;
  p->peer_ctl_asm.at    = 0;
  p->peer_ctl_asm.skip  = 0;
  p->peer_impl_len      = 0;
  p->peer_has_impl      = 0;
  p->hold_len           = 0;
  p->goaway_deadline    = (u64)-1;
  p->goaway_flushed_at  = 0;
  p->closing            = 0;
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    p->tracks[t].in_use = 0;
  moqsess_init(&p->sess);
  p->control_stream_id = 0;
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
  if (moqtrun_find_by_wt(hub, s)) return;
  wired_moqtrun_peer* p = moqtrun_alloc(hub);
  if (!p) return;
  moqtrun_init_peer(hub, p, s, ver, moqtrun_legacy_token(protocol));
}

/* ===================== control-message handlers ===================== */

static void moqtrun_buf_append(u8* buf, usz* len, usz cap, wired_span msg) {
  if (*len + msg.n > cap) return;
  bytes_memcpy(buf + *len, msg.p, msg.n);
  *len += msg.n;
}

static void moqtrun_req_queue(wired_moqtrun_req* q, wired_span msg) {
  int i = q->armed_idx ^ 1;
  moqtrun_buf_append(
      q->send_bufs[i], &q->send_lens[i], WIRED_MOQTRUN_REQ_SEND_BUF, msg);
}

/* Appends one control message's already-encoded bytes to p's per-dispatch
 * reply queue -- moqtrun.h's send_bufs/armed_idx doc explains why this is
 * the OTHER slot from p->armed_idx, never the armed one: every handler
 * queues here instead of calling stream_send itself, so a dispatch with
 * several replies (e.g. one SUBSCRIBE per other peer) still calls
 * stream_send only once. Silently drops on overflow
 * (WIRED_MOQTRUN_CTL_SEND_BUF is sized for the worst case this hub's own
 * protocol subset can produce, so overflow never happens in practice).
 * A message read from a request stream is answered on that stream
 * instead (draft-ietf-moq-transport-19 10.1: responses travel on the
 * request's bidi stream). */
static void moqtrun_queue_reply(wired_moqtrun_peer* p, wired_span msg) {
  int pending_idx = p->armed_idx ^ 1;
  if (p->req) {
    moqtrun_req_queue(p->req, msg);
    return;
  }
  moqtrun_buf_append(
      p->send_bufs[pending_idx], &p->send_lens[pending_idx],
      WIRED_MOQTRUN_CTL_SEND_BUF, msg);
}

/* The request p is handling established a subscription or track. */
static void moqtrun_req_mark_live(wired_moqtrun_peer* p) {
  if (p->req) p->req->live = 1;
}

/* The reassembly of the stream p is handling: a request stream's own,
 * else the control stream moqtrun_ctl_rx selected (ctl_asm when no
 * control dispatch is running). */
static wired_moqtrun_ctl_asm* moqtrun_cur_asm(wired_moqtrun_peer* p) {
  if (p->req) return &p->req->in;
  return p->rx ? p->rx : &p->ctl_asm;
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
/* Nothing to flush, or nothing may flush yet: the hub's control stream
 * has not opened (its SETUP must be the stream's first bytes, so no
 * reply -- GOAWAY included -- may precede it). */
static int moqtrun_flush_idle(const wired_moqtrun_peer* p, int pending_idx) {
  return !p->ctl_opened || p->send_lens[pending_idx] == 0;
}

static void moqtrun_flush_replies(wired_moqt_io* io, wired_moqtrun_peer* p) {
  int pending_idx = p->armed_idx ^ 1;
  if (moqtrun_flush_idle(p, pending_idx)) return;
  int r = io->stream_send(
      p->wt, p->control_stream_id,
      wired_span_of(p->send_bufs[pending_idx], p->send_lens[pending_idx]), 0);
  if (r <= 0) return;
  p->send_lens[p->armed_idx] = 0; /* old armed slot: now safe to reuse */
  p->armed_idx               = pending_idx;
}

/* A request stream's first reply round opens its send side; later rounds
 * append to it. */
static int moqtrun_req_send(
    wired_moqt_io*     io,
    wired_wt_session*  s,
    wired_moqtrun_req* q,
    wired_span         b) {
  if (q->opened) return io->stream_send(s, q->stream_id, b, 0);
  q->opened = io->stream_reply_open(s, q->stream_id, b) > 0;
  return q->opened;
}

/* moqtrun_flush_replies for a request stream's own queue. A successful
 * flush answers every REQUEST_UPDATE coalesced into it at once (draft-19
 * 10.4: "each REQUEST_OK or REQUEST_ERROR response restores one
 * credit"), so the outstanding count resets to 0 rather than ticking
 * down per message. */
static void moqtrun_req_flush(
    wired_moqt_io* io, wired_wt_session* s, wired_moqtrun_req* q) {
  int pending_idx = q->armed_idx ^ 1;
  if (q->send_lens[pending_idx] == 0) return;
  wired_span b =
      wired_span_of(q->send_bufs[pending_idx], q->send_lens[pending_idx]);
  if (moqtrun_req_send(io, s, q, b) <= 0) return;
  q->send_lens[q->armed_idx] = 0;
  q->armed_idx               = pending_idx;
  q->pending_updates         = 0;
}

/* Flushes the queue of the stream p is handling. */
static void moqtrun_flush_cur(wired_moqt_io* io, wired_moqtrun_peer* p) {
  if (p->req) {
    moqtrun_req_flush(io, p->wt, p->req);
    return;
  }
  moqtrun_flush_replies(io, p);
}

static int moqtrun_encode_request_error(
    wired_mspan buf, usz* off, const void* m) {
  return moqctl_request_error_encode(buf, off, m);
}

static void moqtrun_send_request_error(wired_moqtrun_peer* p, u64 code) {
  u8                   msg[WIRED_MOQTRUN_CTL_REPLY_MAX];
  moqctl_request_error e = {0};
  e.error_code           = moqctl_request_error_for(p->ver, code);
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

/* p's ring index recording k, else WIRED_MOQTRUN_SUB_NAMES. */
static usz moqtrun_sub_name_find(const wired_moqtrun_peer* p, moqtrun_key k) {
  for (usz i = 0; i < p->sub_names_n; i++)
    if (moqtrun_sub_name_eq(p, i, k)) return i;
  return WIRED_MOQTRUN_SUB_NAMES;
}

/* 1 iff p has recorded a successful SUBSCRIBE for name. */
static int moqtrun_sub_name_known(const wired_moqtrun_peer* p, moqtrun_key k) {
  return moqtrun_sub_name_find(p, k) < WIRED_MOQTRUN_SUB_NAMES;
}

/* Records k at the ring's write index; returns that index. */
static usz moqtrun_sub_name_store(wired_moqtrun_peer* p, moqtrun_key k) {
  usz at = p->sub_names_at;
  bytes_memcpy(p->sub_names[p->sub_names_at], k.name.p, k.name.n);
  p->sub_name_lens[p->sub_names_at] = k.name.n;
  bytes_memcpy(p->sub_ns[p->sub_names_at], k.ns.p, k.ns.n);
  p->sub_ns_lens[p->sub_names_at] = k.ns.n;
  p->sub_names_at = (u8)((p->sub_names_at + 1) % WIRED_MOQTRUN_SUB_NAMES);
  if (p->sub_names_n < WIRED_MOQTRUN_SUB_NAMES) p->sub_names_n++;
  return at;
}

/* Remember a name p subscribed to, and the subscription's state s, so a
 * later REPUBLISH of it can re-attach p as it was
 * (wired_moqtrun_peer.sub_names' doc). An oversized name could never
 * match a recorded track name, so it is not stored. */
static void moqtrun_note_sub_name(
    wired_moqtrun_peer* p, moqtrun_key k, const wired_moqtrun_sub* s) {
  if (moqtrun_key_oversized(k)) return;
  usz i = moqtrun_sub_name_find(p, k);
  if (i == WIRED_MOQTRUN_SUB_NAMES) i = moqtrun_sub_name_store(p, k);
  p->sub_state[i] = *s;
}

static int moqtrun_encode_request_ok(wired_mspan buf, usz* off, const void* m) {
  return moqctl_request_ok_encode(buf, off, m);
}

/* LARGEST_OBJECT once t (0: no track) has published Objects (10.2.16:
 * SUBSCRIBE_OK, REQUEST_UPDATE_OK and TRACK_STATUS_OK carry it). */
static void moqtrun_largest_param(
    moqctl_params* params, const wired_moqtrun_track* t);

/* REQUEST_OK; answering a request about track t (0: none), it carries the
 * Largest Location. */
static void moqtrun_queue_request_ok(
    wired_moqtrun_peer* p, const wired_moqtrun_track* t) {
  u8                msg[WIRED_MOQTRUN_CTL_REPLY_MAX];
  moqctl_request_ok ok = {0};
  moqtrun_largest_param(&ok.params, t);
  usz n = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_REQUEST_OK,
      moqtrun_encode_request_ok, &ok);
  moqtrun_queue_reply(p, wired_span_of(msg, n));
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
    usz                  si,
    u32                  code) {
  if (!moqtrun_relay_orphan_ok(t, r, si)) return;
  wired_moqtrun_peer* dst = &hub->peers[t->subs[si].session_idx];
  if (dst->in_use) hub->io.stream_reset(dst->wt, r->sub_stream_id[si], code);
  r->sub_stream_set[si] = 0;
}

static void moqtrun_relay_reset_stale(
    wired_moqt_hub* hub, wired_moqtrun_track* t, wired_moqtrun_relay* r) {
  if (!r->in_use) return;
  for (usz si = 0; si < WIRED_MOQTRUN_MAX_SUBS; si++)
    moqtrun_relay_reset_one_sub(hub, t, r, si, MOQTRUN_RESET_INTERNAL_ERROR);
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

/* A live track's incarnation ends: its cached Objects go (a slot never
 * claimed holds no tag worth trusting). */
static void moqtrun_track_cache_drop(
    wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  if (t->in_use) moqcache_release(&hub->cache, t->cache_tag);
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
  moqtrun_track_cache_drop(hub, t);
  if (!t->in_use) moqtrun_track_clear_subs(t);
  t->cache_tag   = ++hub->cache_tag_next;
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

/* SUBSCRIBE_TRACKS's own section: resets every hub-opened PUBLISH stream
 * for the track incarnation tag (T-07/T-08), defined there. */
static void moqtrun_subtracks_track_gone(wired_moqt_hub* hub, u64 tag);

/* Frees a superseded track: its subscribers' still-open relay streams are
 * reset (moqtrun_track_reset_stale_relays' own doc), its rings go back to
 * the pool (holds released), and the slot stops matching any name or Track
 * Alias, so the lingering session's stray Objects are dropped instead of
 * relayed. */
static void moqtrun_track_retire(wired_moqt_hub* hub, wired_moqtrun_track* t) {
  moqtrun_track_reset_stale_relays(hub, t);
  moqtrun_track_cache_drop(hub, t);
  moqtrun_track_return_rings(hub, t);
  moqtrun_track_clear_relays(t);
  moqtrun_subtracks_track_gone(hub, t->cache_tag);
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

static int moqtrun_publish_refused(
    const wired_moqt_hub* hub, const moqctl_publish* m, u64* code);

static u64 moqtrun_prop_sgt_of(const moqkvp* kv, u64 prior) {
  return kv->type == MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT && !kv->is_raw
             ? kv->num
             : prior;
}

/* The SUBGROUP_DELIVERY_TIMEOUT Track Property (12.6, Type 0x06) of a
 * PUBLISH's Track Properties (KVPs to the end of the body, SS1.6); 0
 * when absent, unknown properties skipped, a malformed pair ends the
 * scan with what was read. */
static u64 moqtrun_track_prop_sgt(wired_span props) {
  usz    off  = 0;
  u64    prev = 0, out = 0;
  moqkvp kv;
  while (off < props.n && moqkvp_take(props, &off, &prev, &kv) == MOQKVP_OK)
    out = moqtrun_prop_sgt_of(&kv, out);
  return out;
}

/* A vetted PUBLISH: claim a track into a free (or matching-name) slot
 * and reply REQUEST_OK; a third distinct track name (no free slot), or a
 * name a newer session already owns (moqtrun_publish_slot), gets
 * REQUEST_ERROR instead of silently overwriting an existing track. */
static void moqtrun_publish_checked(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    usz                   peer_idx,
    const moqctl_publish* m) {
  u8  ns_buf[WIRED_MOQTRUN_MAX_NS];
  u64 code;
  if (moqtrun_publish_refused(hub, m, &code)) {
    moqtrun_send_request_error(p, code);
    return;
  }
  moqtrun_key          k = moqtrun_key_of(&m->name, ns_buf);
  wired_moqtrun_track* t = moqtrun_publish_slot(hub, p, peer_idx, k);
  if (!t) {
    moqtrun_send_request_error(p, MOQCTL_ERR_NOT_SUPPORTED);
    return;
  }
  moqtrun_supersede_name(hub, peer_idx, k);
  moqtrun_track_claim(hub, t, k, m->track_alias);
  moqtrun_track_seed_largest(t, &m->params);
  t->request_id          = m->request_id;
  t->subgroup_timeout_ms = moqtrun_track_prop_sgt(m->track_properties);
  t->up_streams          = 0;
  t->pubdone_pending     = 0;
  moqtrun_reattach_subs(hub, t, peer_idx, k);
  moqtrun_queue_request_ok(p, 0);
  moqtrun_req_mark_live(p);
}

/* draft SS10.9 PUBLISH: decode, then authorize and claim
 * (moqtrun_publish_checked). */
static void moqtrun_handle_publish(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  usz            off = 0;
  moqctl_publish m;
  if (moqctl_publish_take(p->ver, body, &off, &m) != MOQCTL_OK) return;
  moqtrun_publish_checked(hub, p, peer_idx, &m);
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

/* --- Track Alias per subscriber session (draft-22 3.1.3, draft-19 11.1):
 * on each subscriber's session the HUB is the publisher, so it picks the
 * alias SUBSCRIBE_OK / its own PUBLISH names, and two Tracks MUST NOT
 * share one within that session -- yet every publisher picks its own,
 * so two publishers' tracks can carry the same number. The hub prefers
 * the publisher's own alias (relayed bytes then pass verbatim), else the
 * lowest free one, and re-spells each relayed SUBGROUP_HEADER /
 * OBJECT_DATAGRAM to its destination's alias (moqtrun_alias_splice). --- */

/* 1 iff s is session pi's Established subscription under alias a. */
static int moqtrun_sub_holds_alias(const wired_moqtrun_sub* s, usz pi, u64 a) {
  return s->active && s->session_idx == pi && s->track_alias == a;
}

static int moqtrun_subs_hold_alias(
    const wired_moqtrun_track* x, usz pi, u64 a) {
  for (usz s = 0; s < WIRED_MOQTRUN_MAX_SUBS; s++)
    if (moqtrun_sub_holds_alias(&x->subs[s], pi, a)) return 1;
  return 0;
}

/* 1 iff x, a live track other than t, gives session pi alias a. */
static int moqtrun_track_alias_clash(
    const wired_moqtrun_track* x, const wired_moqtrun_track* t, usz pi, u64 a) {
  return x != t && x->in_use && moqtrun_subs_hold_alias(x, pi, a);
}

static int moqtrun_peer_tracks_clash(
    const wired_moqtrun_peer* q, const wired_moqtrun_track* t, usz pi, u64 a) {
  for (usz k = 0; k < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; k++)
    if (moqtrun_track_alias_clash(&q->tracks[k], t, pi, a)) return 1;
  return 0;
}

static int moqtrun_peer_clash(
    const wired_moqtrun_peer* q, const wired_moqtrun_track* t, usz pi, u64 a) {
  return q->in_use && moqtrun_peer_tracks_clash(q, t, pi, a);
}

static int moqtrun_peers_clash(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t, usz pi, u64 a) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (moqtrun_peer_clash(&hub->peers[i], t, pi, a)) return 1;
  return 0;
}

/* The hub's own blob/live track x: its framed bytes always carry
 * own_alias, so that alias is reserved in every session. */
static int moqtrun_own_alias_clash(
    const wired_moqtrun_track* x, const wired_moqtrun_track* t, u64 a) {
  return x != t && x->in_use && x->own_alias == a;
}

static int moqtrun_own_clash(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t, u64 a) {
  return moqtrun_own_alias_clash(&hub->blob_track, t, a) ||
         moqtrun_own_alias_clash(&hub->live.track, t, a);
}

static moqtrun_key moqtrun_track_key(const wired_moqtrun_track* t) {
  moqtrun_key k;
  k.ns   = wired_span_of(t->ns, t->ns_len);
  k.name = wired_span_of(t->name, t->name_len);
  return k;
}

/* Ring entry i of p: a subscription to another Track than t under alias
 * a, which p's client may still believe Established (a REPUBLISH
 * re-attaches it under that alias, moqtrun_reattach_one_sub). A
 * forgotten (cancelled) entry's name is over-long and never counts. */
static int moqtrun_sub_state_clash(
    const wired_moqtrun_peer* p, usz i, const wired_moqtrun_track* t, u64 a) {
  return p->sub_state[i].track_alias == a &&
         p->sub_name_lens[i] <= WIRED_MOQTRUN_MAX_NAME &&
         !moqtrun_sub_name_eq(p, i, moqtrun_track_key(t));
}

static int moqtrun_ring_clash(
    const wired_moqtrun_peer* p, const wired_moqtrun_track* t, u64 a) {
  for (usz i = 0; i < p->sub_names_n; i++)
    if (moqtrun_sub_state_clash(p, i, t, a)) return 1;
  return 0;
}

/* 1 iff q is a PUBLISH this hub opened on session wt. */
static int moqtrun_req_is_pub_on(
    const wired_moqtrun_req* q, const wired_wt_session* wt) {
  return q->in_use && q->pub_origin_rid && q->wt == wt;
}

static int moqtrun_req_alias_clash(
    const wired_moqtrun_req*   q,
    const wired_wt_session*    wt,
    const wired_moqtrun_track* t,
    u64                        a) {
  return moqtrun_req_is_pub_on(q, wt) && q->pub_track_tag != t->cache_tag &&
         q->pub_alias == a;
}

static int moqtrun_reqs_clash(
    const wired_moqt_hub*      hub,
    const wired_wt_session*    wt,
    const wired_moqtrun_track* t,
    u64                        a) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    if (moqtrun_req_alias_clash(&hub->reqs[i], wt, t, a)) return 1;
  return 0;
}

/* Session pi already names another Track than t by a: a subscription,
 * a hub track's reserved alias, a remembered subscription, or a PUBLISH
 * the hub opened there. */
static int moqtrun_alias_live(
    const wired_moqt_hub* hub, usz pi, const wired_moqtrun_track* t, u64 a) {
  return moqtrun_peers_clash(hub, t, pi, a) || moqtrun_own_clash(hub, t, a);
}

static int moqtrun_alias_kept(
    const wired_moqt_hub* hub, usz pi, const wired_moqtrun_track* t, u64 a) {
  const wired_moqtrun_peer* p = &hub->peers[pi];
  return moqtrun_ring_clash(p, t, a) || moqtrun_reqs_clash(hub, p->wt, t, a);
}

static int moqtrun_alias_taken(
    const wired_moqt_hub* hub, usz pi, const wired_moqtrun_track* t, u64 a) {
  return moqtrun_alias_live(hub, pi, t, a) || moqtrun_alias_kept(hub, pi, t, a);
}

/* The Track Alias session pi knows t by: t's own (publisher-chosen) alias
 * unless another Track holds it there, else the lowest free one. */
static u64 moqtrun_session_alias(
    const wired_moqt_hub* hub, usz pi, const wired_moqtrun_track* t) {
  u64 a = 0;
  if (!moqtrun_alias_taken(hub, pi, t, t->own_alias)) return t->own_alias;
  while (moqtrun_alias_taken(hub, pi, t, a)) a++;
  return a;
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
  return moqctl_params_find(&m->params, type);
}

static u8 moqtrun_param_u8(const moqctl_param* p) { return p ? (u8)p->u8v : 0; }

static u64 moqtrun_param_vi(const moqctl_param* p) { return p ? p->vi : 0; }

/* FORWARD omitted defaults to 1 (10.2.17). */
static u8 moqtrun_forward_off(const moqctl_param* p) {
  return p && p->u8v == 0;
}

/* t's Largest Location, 0 when t (0: no track) published nothing. */
static const moqctl_loc* moqtrun_track_top(const wired_moqtrun_track* t) {
  return t && t->has_largest ? &t->largest : 0;
}

/* A filter's Start Location (19 SS5.1.2, 22 SS9.20.9) against top, the
 * Largest Object (0: nothing published), indexed by moqctl_rsk. */
typedef moqctl_loc (*moqtrun_start_fn)(
    const moqctl_loc*, const moqctl_rangeloc*);

/* {Largest.Group + 1 - n, 0}, floored at group 0; n 0 is draft-19's Next
 * Group Start. */
static moqctl_loc moqtrun_start_rel(
    const moqctl_loc* top, const moqctl_rangeloc* f) {
  u64 next = top ? top->group + 1 : 0;
  return moqctl_loc_of(next - u64_min(f->start_group, next), 0);
}

/* Next Object (draft-19's Largest Object filter): {Largest.Group,
 * Largest.Object + 1}, {0, 0} when nothing was published. */
static moqctl_loc moqtrun_start_next(
    const moqctl_loc* top, const moqctl_rangeloc* f) {
  (void)f;
  return top ? moqctl_loc_of(top->group, top->object + 1) : moqctl_loc_of(0, 0);
}

static moqctl_loc moqtrun_start_abs(
    const moqctl_loc* top, const moqctl_rangeloc* f) {
  (void)top;
  return moqctl_loc_of(f->start_group, f->start_object);
}

static const moqtrun_start_fn MOQTRUN_START_FNS[] = {
    moqtrun_start_rel, moqtrun_start_next, moqtrun_start_abs};

/* s's start/end from its filter (unfiltered: everything from {0, 0}),
 * resolved against t now -- at SUBSCRIBE, update and re-attach alike. */
static void moqtrun_sub_resolve(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t) {
  s->start          = moqctl_loc_of(0, 0);
  s->has_end_group  = 0;
  s->has_end_object = 0;
  if (!s->has_filter) return;
  s->start = MOQTRUN_START_FNS[s->filter.sk](moqtrun_track_top(t), &s->filter);
  s->has_end_group  = s->filter.ek != MOQCTL_REK_UNBOUNDED;
  s->has_end_object = s->filter.ek == MOQCTL_REK_OBJ;
  s->end_group      = s->filter.end_group;
  s->end_object     = s->filter.end_object;
}

static int moqtrun_param_has_filter(const moqctl_param* f) {
  return f && f->has_filter;
}

/* LOCATION_FILTER f (0, or draft-22 type 0x00: unfiltered) onto s. */
static void moqtrun_sub_filter(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* f) {
  s->has_filter = (u8)moqtrun_param_has_filter(f);
  if (s->has_filter) s->filter = f->rl;
  moqtrun_sub_resolve(s, t);
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

/* ===== Range Filters (draft-19 10.2.10-10.2.14) ===== */

static int moqtrun_ptype_is_rngf(u64 t) {
  return t >= MOQCTL_PARAM_SUBGROUP_FILTER &&
         t <= MOQCTL_PARAM_TRACK_PROPERTY_FILTER;
}

/* Decodes item's Range Filter value into *f; 0 when item is not a
 * Range Filter parameter. An undecodable value is surfaced as
 * f->invalid: the message layer answers INVALID_FILTER. */
static int moqtrun_rngf_of(const moqctl_param* it, moqctl_rangefilter* f) {
  if (!moqtrun_ptype_is_rngf(it->type)) return 0;
  if (moqctl_rangefilter_take(it->type, it->bytes, f) != MOQCTL_OK)
    f->invalid = 1;
  return 1;
}

/* Flattens f's Ranges into s->rngf rows (capacity was vetted by
 * moqtrun_rngf_refusal / moqtrun_rngf_over before apply). */
static void moqtrun_rngf_add(
    wired_moqtrun_sub* s, u64 ptype, const moqctl_rangefilter* f) {
  for (usz i = 0; i < f->n && s->rngf_n < WIRED_MOQTRUN_MAX_FILTER_RANGES;
       i++) {
    wired_moqtrun_rngrow* r = &s->rngf[s->rngf_n++];
    r->ptype                = ptype;
    r->set_id               = (u8)f->set_id;
    r->has_prop             = (u8)f->has_prop;
    r->prop_type            = f->prop_type;
    r->start                = f->r[i].start;
    r->end                  = f->r[i].end;
    r->has_end              = (u8)f->r[i].has_end;
  }
}

static void moqtrun_rngf_add_item(
    wired_moqtrun_sub* s, const moqctl_param* it) {
  moqctl_rangefilter f;
  if (!moqtrun_rngf_of(it, &f)) return;
  moqtrun_rngf_add(s, it->type, &f);
}

/* SUBSCRIBE: the message is the subscription's whole Range Filter set. */
static void moqtrun_sub_rngf_set(
    wired_moqtrun_sub* s, const moqctl_params* params) {
  s->rngf_n = 0;
  for (usz i = 0; i < params->n; i++)
    moqtrun_rngf_add_item(s, &params->items[i]);
}

static int moqtrun_rngf_msg_has(const moqctl_params* params, u64 ptype) {
  for (usz i = 0; i < params->n; i++)
    if (params->items[i].type == ptype) return 1;
  return 0;
}

/* Drops s's rows of every filter type the update mentions (10.2.10: a
 * non-zero Length replaces that entire filter parameter, a zero Length
 * removes it; an omitted type stays). */
static void moqtrun_rngf_drop_mentioned(
    wired_moqtrun_sub* s, const moqctl_params* params) {
  usz w = 0;
  for (usz i = 0; i < s->rngf_n; i++)
    if (!moqtrun_rngf_msg_has(params, s->rngf[i].ptype))
      s->rngf[w++] = s->rngf[i];
  s->rngf_n = (u8)w;
}

/* REQUEST_UPDATE: replace/remove the mentioned types, keep the rest. */
static void moqtrun_sub_rngf_update(
    wired_moqtrun_sub* s, const moqctl_params* params) {
  moqtrun_rngf_drop_mentioned(s, params);
  for (usz i = 0; i < params->n; i++)
    moqtrun_rngf_add_item(s, &params->items[i]);
}

static int moqtrun_row_in(const wired_moqtrun_rngrow* r, u64 v) {
  return v >= r->start && (!r->has_end || v <= r->end);
}

static int moqtrun_row_oid_of_set(const wired_moqtrun_rngrow* r, u8 set) {
  return r->set_id == set && r->ptype == MOQCTL_PARAM_OBJECTID_FILTER;
}

/* OBJECTID rows of one set OR together; a set without any (or with only
 * filter types the delivery gates cannot see) passes. have/hit are 0/1
 * flags combined bitwise to keep the loop body branch-free. */
static int moqtrun_set_oid_pass(const wired_moqtrun_sub* s, u8 set, u64 oid) {
  int have = 0, hit = 0;
  for (usz i = 0; i < s->rngf_n; i++) {
    int in = moqtrun_row_oid_of_set(&s->rngf[i], set);
    have |= in;
    hit |= in & moqtrun_row_in(&s->rngf[i], oid);
  }
  return hit | !have;
}

/* SetIDs OR together (10.2.10): the Object passes when any set's
 * evaluable params all admit it; no rows at all is unfiltered. */
static int moqtrun_sub_rngf_pass(const wired_moqtrun_sub* s, u64 oid) {
  int pass = !s->rngf_n; /* no rows: unfiltered */
  for (usz i = 0; i < s->rngf_n; i++)
    pass |= moqtrun_set_oid_pass(s, s->rngf[i].set_id, oid);
  return pass;
}

/* min over the non-zero of {publisher's Track Property, subscriber's
 * parameter} (draft-19 8); 0 = neither set a timeout. */
static u64 moqtrun_timeout_min(u64 pub_ms, u64 sub_ms) {
  if (!pub_ms) return sub_ms;
  if (!sub_ms) return pub_ms;
  return u64_min(pub_ms, sub_ms);
}

static u64 moqtrun_sub_sgt(
    const wired_moqtrun_track* t, const moqctl_subscribe* m) {
  return moqtrun_timeout_min(
      t->subgroup_timeout_ms, moqtrun_param_vi(moqtrun_sub_param(
                                  m, MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT)));
}

/* Opens slot s on t for peer_idx under alias, its state taken from
 * SUBSCRIBE m. */
static void moqtrun_sub_open(
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    usz                        peer_idx,
    u64                        alias,
    const moqctl_subscribe*    m) {
  s->session_idx  = peer_idx;
  s->track_alias  = alias;
  s->active       = 1;
  s->request_id   = m->request_id;
  s->blob_sent    = 0;
  s->stream_count = 0;
  s->jl           = t->largest;
  s->has_jl       = (u8)t->has_largest;
  moqtrun_sub_scalars(s, m);
  s->subgroup_timeout = moqtrun_sub_sgt(t, m);
  moqtrun_sub_rngf_set(s, &m->params);
  moqtrun_sub_filter(s, t, moqtrun_sub_param(m, MOQCTL_PARAM_LOCATION_FILTER));
}

/* 1 iff Objects go to s: Established and not FORWARD 0 (10.2.17). */
static int moqtrun_sub_forwards(const wired_moqtrun_sub* s) {
  return s->active && !s->forward_off;
}

/* 1 iff Group g passes s's Location Filter (5.1.4): not before the start
 * Group, not past the end Group. */
static int moqtrun_sub_wants_group(const wired_moqtrun_sub* s, u64 g) {
  return g >= s->start.group && !(s->has_end_group && g > s->end_group);
}

/* 1 iff l is past an explicit End Object (draft-22 0x04) in its Group. */
static int moqtrun_sub_past_end_object(
    const wired_moqtrun_sub* s, moqctl_loc l) {
  return s->has_end_object && l.group == s->end_group &&
         l.object > s->end_object;
}

/* Forward AND Location Filter (5.1.5) for a stream of Group g.
 * ponytail: Group-granular on the START side only -- Objects of the start
 * Group below the start Object still pass whole (cutting the FRONT of a
 * round means re-framing past the SUBGROUP_HEADER, not just shortening the
 * tail, so it needs its own design); cut rounds at those Objects if a
 * filter ever starts mid-Group on a many-Object stream. The END side (a
 * draft-22 End Object mid-round) is already cut by moqtrun_wire_cutoff. */
static int moqtrun_sub_gets(const wired_moqtrun_sub* s, u64 g) {
  return moqtrun_sub_forwards(s) && moqtrun_sub_wants_group(s, g);
}

/* 1 iff sub's End Object could fall somewhere inside Group group's wire
 * at all -- the moqtrun_wire_cutoff guard, split out to keep its own
 * branch count at the CCN gate. */
static int moqtrun_end_object_in_group(const wired_moqtrun_sub* s, u64 group) {
  return s->has_end_object && group == s->end_group;
}

/* moqtrun_wire_cutoff's decode walk, once its guard already confirmed s has
 * an End Object in this Group -- split out to keep moqtrun_wire_cutoff's
 * own branch count at the CCN gate. */
static usz moqtrun_cutoff_scan(
    const wired_moqtrun_sub* s,
    wired_span               wire,
    usz                      off0,
    moqdata_objseq           seq0) {
  usz         off = off0, cut = off0;
  moqdata_obj obj;
  while (moqdata_obj_take(wire, &off, &seq0, &obj) == MOQDATA_OK) {
    if (obj.object_id > s->end_object) return cut;
    cut = off;
  }
  return cut;
}

/* Byte offset in wire right after the last Object sub may still receive
 * this round: wire.n when sub has no End Object in Group g, or when none
 * of wire's Objects (decoded from off0/seq0, e.g. right after a
 * SUBGROUP_HEADER, or a header-less continuation's saved seq) crosses it.
 * draft-22 0x04's End Object is inclusive and Object-granular (SS3.3.1:
 * "a publisher MUST NOT send objects from outside the requested range"),
 * so a round carrying several Objects of the same Group is cut right
 * after the End Object, never re-framed past it. */
static usz moqtrun_wire_cutoff(
    const wired_moqtrun_sub* s,
    wired_span               wire,
    usz                      off0,
    moqdata_objseq           seq0,
    u64                      group) {
  if (!moqtrun_end_object_in_group(s, group)) return wire.n;
  return moqtrun_cutoff_scan(s, wire, off0, seq0);
}

/* moqtrun_sub_gets for one Object at l (a datagram): also not before the
 * start Object nor past an End Object. */
static int moqtrun_sub_in_objects(const wired_moqtrun_sub* s, moqctl_loc l) {
  return !moqctl_loc_less(l, s->start) && !moqtrun_sub_past_end_object(s, l);
}

static int moqtrun_sub_gets_loc(const wired_moqtrun_sub* s, moqctl_loc l) {
  return moqtrun_sub_gets(s, l.group) && moqtrun_sub_in_objects(s, l) &&
         moqtrun_sub_rngf_pass(s, l.object);
}

static int moqtrun_late_by(u64 timeout_ms, u64 age_ms) {
  return timeout_ms != 0 && age_ms > timeout_ms;
}

/* draft 8: an Object whose first byte reached the hub age_ms ago is past
 * s's OBJECT_DELIVERY_TIMEOUT or its effective SUBGROUP_DELIVERY_TIMEOUT
 * (0: none). */
static int moqtrun_sub_late(const wired_moqtrun_sub* s, u64 age_ms) {
  return moqtrun_late_by(s->delivery_timeout, age_ms) ||
         moqtrun_late_by(s->subgroup_timeout, age_ms);
}

/* A re-attached subscription meets a new incarnation: a Largest-relative
 * filter start (9.3.1) and the Joining Location (5.1) are resolved again
 * against its Largest -- the stored ones name the old incarnation's
 * Objects. An absolute filter keeps the subscriber's own Locations. */
static void moqtrun_sub_reresolve(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t) {
  moqtrun_sub_resolve(s, t);
  s->jl     = t->largest;
  s->has_jl = (u8)t->has_largest;
}

/* Re-attaches peer i to track with the state it SUBSCRIBEd to k with
 * (Forward State, Request ID, parameters: only the subscriber changes
 * them, draft 5.1) under the alias its SUBSCRIBE_OK named -- the one its
 * client still holds (draft-22 3.1.3; moqtrun_session_alias kept it
 * reserved). */
static void moqtrun_reattach_one_sub(
    wired_moqt_hub* hub, wired_moqtrun_track* track, usz i, moqtrun_key k) {
  wired_moqtrun_sub* slot = moqtrun_sub_slot(track);
  if (!slot) return;
  const wired_moqtrun_peer* p = &hub->peers[i];
  *slot                       = p->sub_state[moqtrun_sub_name_find(p, k)];
  slot->session_idx           = i;
  slot->active                = 1;
  moqtrun_sub_reresolve(slot, track);
}

/* A (re)PUBLISHed name re-attaches every still-connected peer that had
 * subscribed to it before -- silently, with no SUBSCRIBE_OK: the
 * subscriber's client still believes its original subscription stands
 * (that belief, standing while the hub-side subscription had died with
 * the publisher's previous incarnation, is exactly the played-into-
 * silence bug this repairs). The relayed bytes are re-spelled to the
 * alias the client already holds (moqtrun_alias_splice), so no
 * client-visible state needs renegotiating. */
static void moqtrun_reattach_subs(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    usz                  pub_idx,
    moqtrun_key          k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (moqtrun_reattach_wanted(hub, track, i, pub_idx, k))
      moqtrun_reattach_one_sub(hub, track, i, k);
}

static int moqtrun_encode_subscribe_ok(
    wired_mspan buf, usz* off, const void* m) {
  return moqctl_subscribe_ok_encode(buf, off, m);
}

static void moqtrun_largest_param(
    moqctl_params* params, const wired_moqtrun_track* t) {
  const moqctl_loc* top = moqtrun_track_top(t);
  params->items[0].type = MOQCTL_PARAM_LARGEST_OBJECT;
  params->items[0].enc  = MOQCTL_PENC_LOCATION;
  params->n             = top != 0;
  if (top) params->items[0].loc = *top;
}

/* SUBSCRIBE_OK with alias; LARGEST_OBJECT once t has published Objects
 * (MUST, draft 10.2.16). */
static void moqtrun_queue_subscribe_ok(
    wired_moqtrun_peer* p, const wired_moqtrun_track* t, u64 alias) {
  u8                  msg[WIRED_MOQTRUN_CTL_REPLY_MAX];
  moqctl_subscribe_ok ok = {0};
  ok.track_alias         = alias;
  moqtrun_largest_param(&ok.params, t);
  usz n = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_SUBSCRIBE_OK,
      moqtrun_encode_subscribe_ok, &ok);
  moqtrun_queue_reply(p, wired_span_of(msg, n));
  moqtrun_req_mark_live(p);
}

static void moqtrun_fill_on_subscribe(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* track,
    wired_moqtrun_sub*   sub,
    const moqctl_params* params);

/* Records slot (peer_idx, its session's alias for track) against track,
 * replies SUBSCRIBE_OK with that alias and opens any requested fill. */
static void moqtrun_accept_subscribe(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    wired_moqtrun_track*    track,
    wired_moqtrun_sub*      slot,
    usz                     peer_idx,
    const moqctl_subscribe* m) {
  moqtrun_sub_open(
      slot, track, peer_idx, moqtrun_session_alias(hub, peer_idx, track), m);
  moqtrun_queue_subscribe_ok(p, track, slot->track_alias);
  moqtrun_fill_on_subscribe(hub, p, track, slot, &m->params);
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
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_sub* slot) {
  if (!moqtrun_sub_forwards(slot)) return 1;
  slot->blob_sent = hub->io.send_uni(p->wt, hub->blob_wire) >= 0;
  hub->stat_open_drop += !slot->blob_sent;
  slot->stream_count += slot->blob_sent;
  return slot->blob_sent;
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

/* A SUBSCRIBE for a track this peer already subscribes: draft-18 6.3
 * allows one subscription per Track and role, so it is refused with
 * DUPLICATE_SUBSCRIPTION; draft-19/22 allow several, and the hub
 * re-answers SUBSCRIBE_OK with the held alias instead of eating another
 * slot (the client resends SUBSCRIBE until a chunk arrives). 1 when held
 * was answered either way, 0 when there is nothing held. */
static int moqtrun_sub_held_reply(
    wired_moqtrun_peer*        p,
    const wired_moqtrun_track* t,
    const wired_moqtrun_sub*   held) {
  if (!held) return 0;
  if (moqver_caps(p->ver) & MOQVER_CAP_DUP_SUBSCRIPTION)
    moqtrun_send_request_error(p, MOQCTL_ERR_DUPLICATE_SUBSCRIPTION);
  else
    moqtrun_queue_subscribe_ok(p, t, held->track_alias);
  return 1;
}

/* SUBSCRIBE for the hub's own blob track: a held subscription is
 * re-answered (moqtrun_sub_held_reply), anyone else gets the blob now. */
static void moqtrun_subscribe_blob(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m) {
  wired_moqtrun_sub* held =
      moqtrun_track_sub_of_peer(&hub->blob_track, peer_idx);
  if (moqtrun_sub_held_reply(p, &hub->blob_track, held)) return;
  moqtrun_blob_send_first(hub, p, peer_idx, m);
}

/* SUBSCRIBE on a found peer track: a held subscription is re-answered
 * (moqtrun_sub_held_reply), anyone else gets a fresh slot, or
 * DOES_NOT_EXIST once the table is full. */
static void moqtrun_subscribe_peer_track(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    wired_moqtrun_track*    track,
    usz                     peer_idx,
    moqtrun_key             k,
    const moqctl_subscribe* m) {
  wired_moqtrun_sub* held = moqtrun_track_sub_of_peer(track, peer_idx);
  if (moqtrun_sub_held_reply(p, track, held)) return;
  wired_moqtrun_sub* slot = moqtrun_sub_slot(track);
  if (!slot) {
    moqtrun_send_request_error(p, MOQCTL_ERR_DOES_NOT_EXIST);
    return;
  }
  moqtrun_accept_subscribe(hub, p, track, slot, peer_idx, m);
  moqtrun_note_sub_name(p, k, slot);
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
  moqtrun_subscribe_peer_track(hub, p, track, peer_idx, k, m);
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

static int moqtrun_ns_field_eq(wired_span f, const char* z, usz n) {
  return f.n == n && !ct_diffn(f.p, (const u8*)z, n);
}

/* draft-19 2.4.2/2.4.3 reserved namespaces: a first Track Namespace
 * field of exactly "." MUST be rejected DOES_NOT_EXIST; ".session"
 * names session-level tracks, and this hub defines none, so every
 * request for one is unrecognized and DOES_NOT_EXIST too. Any other
 * "."-led field is an unrecognized reserved namespace and passes to
 * the application (this hub's normal handling). */
static int moqtrun_ns_reserved(const moqctl_ns* ns) {
  if (!ns->n) return 0;
  return moqtrun_ns_field_eq(ns->fields[0], ".", 1) ||
         moqtrun_ns_field_eq(ns->fields[0], ".session", 8);
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

/* draft-22 16.3 "Preventing Impersonation" (the same MUST in every
 * draft): a relay verifies the publisher may claim the PUBLISH's Full
 * Track Name. Every PUBLISH passes here before any slot is claimed,
 * moqtrun_subscribe_refused's twin. 1 + *code when refused. */
static int moqtrun_publish_auth_refused(
    const wired_moqt_hub* hub, const moqctl_publish* m, u64* code) {
  const moqctl_token* t = moqtrun_auth_token_of(&m->params);
  *code                 = MOQCTL_ERR_MALFORMED_AUTH_TOKEN;
  if (moqtrun_token_uses_alias(t)) return 1;
  *code = MOQCTL_ERR_UNAUTHORIZED;
  if (!hub->authorize_publish) return 0;
  return !hub->authorize_publish(hub->authorize_pub_ctx, &m->name, t);
}

/* Reserved namespaces first (2.4.2/2.4.3: never published under), then
 * authorization. */
static int moqtrun_publish_refused(
    const wired_moqt_hub* hub, const moqctl_publish* m, u64* code) {
  *code = MOQCTL_ERR_DOES_NOT_EXIST;
  if (moqtrun_ns_reserved(&m->name.ns)) return 1;
  return moqtrun_publish_auth_refused(hub, m, code);
}

/* Not a REQUEST_ERROR code: the request is accepted. */
#define MOQTRUN_REQ_ACCEPT (~(u64)0)

/* draft-22 0x04 whose End Object precedes its Start Object in the same
 * Group: no Object can pass (SS9.20.9; INVALID_RANGE, SS12.3). */
static int moqtrun_filter_inverted(const moqctl_rangeloc* f) {
  return f->ek == MOQCTL_REK_OBJ &&
         moqctl_loc_less(
             moqctl_loc_of(f->end_group, f->end_object),
             moqctl_loc_of(f->start_group, f->start_object));
}

static int moqtrun_params_inverted(const moqctl_params* params) {
  const moqctl_param* f =
      moqctl_params_find(params, MOQCTL_PARAM_LOCATION_FILTER);
  return moqtrun_param_has_filter(f) && moqtrun_filter_inverted(&f->rl);
}

static int moqtrun_rngf_dup_pair(
    const moqctl_rangefilter* a, const moqctl_rangefilter* b) {
  return a->set_id == b->set_id && a->prop_type == b->prop_type;
}

static int moqtrun_rngf_dup_j(
    const moqctl_params*      params,
    usz                       j,
    u64                       type,
    const moqctl_rangefilter* fi) {
  moqctl_rangefilter fj;
  if (params->items[j].type != type) return 0;
  moqtrun_rngf_of(&params->items[j], &fj);
  return moqtrun_rngf_dup_pair(fi, &fj);
}

/* A repeated (Type, SetID, Property Type) identity earlier in the same
 * message (10.2.10: INVALID_FILTER). */
static int moqtrun_rngf_dup_before(
    const moqctl_params* params, usz i, const moqctl_rangefilter* fi) {
  for (usz j = 0; j < i; j++)
    if (moqtrun_rngf_dup_j(params, j, params->items[i].type, fi)) return 1;
  return 0;
}

typedef struct {
  usz count; /* total Ranges across the message's Range Filters */
  int bad;   /* malformed value or repeated identity */
} moqtrun_rngf_scan;

static void moqtrun_rngf_scan_one(
    const moqctl_params* params, usz i, moqtrun_rngf_scan* s) {
  moqctl_rangefilter f;
  if (!moqtrun_rngf_of(&params->items[i], &f)) return;
  s->count += f.n;
  s->bad |= f.invalid | moqtrun_rngf_dup_before(params, i, &f);
}

static moqtrun_rngf_scan moqtrun_rngf_scan_msg(const moqctl_params* params) {
  moqtrun_rngf_scan s = {0, 0};
  for (usz i = 0; i < params->n; i++) moqtrun_rngf_scan_one(params, i, &s);
  return s;
}

/* INVALID_FILTER (10.2.10/10.4) for a malformed Range Filter value, a
 * repeated (Type, SetID, Property Type) identity, or more Ranges than
 * the hub's advertised MAX_FILTER_RANGES; ACCEPT otherwise. */
static u64 moqtrun_rngf_refusal(const moqctl_params* params) {
  moqtrun_rngf_scan s = moqtrun_rngf_scan_msg(params);
  if (s.bad || s.count > WIRED_MOQTRUN_MAX_FILTER_RANGES)
    return MOQCTL_ERR_INVALID_FILTER;
  return MOQTRUN_REQ_ACCEPT;
}

/* Rows s would hold after the update: kept types plus the message's
 * (10.4: MAX_FILTER_RANGES bounds the concurrent total). */
static int moqtrun_rngf_over(
    const wired_moqtrun_sub* s, const moqctl_params* params) {
  usz kept = 0;
  for (usz i = 0; i < s->rngf_n; i++)
    kept += !moqtrun_rngf_msg_has(params, s->rngf[i].ptype);
  return kept + moqtrun_rngf_scan_msg(params).count >
         WIRED_MOQTRUN_MAX_FILTER_RANGES;
}

/* REQUEST_ERROR code a SUBSCRIBE's or REQUEST_UPDATE's parameters call
 * for: a bad Range Filter, an unsatisfiable Location Filter. */
static u64 moqtrun_params_refusal(const moqctl_params* params) {
  u64 code = moqtrun_rngf_refusal(params);
  if (code != MOQTRUN_REQ_ACCEPT) return code;
  return moqtrun_params_inverted(params) ? MOQCTL_ERR_INVALID_RANGE
                                         : MOQTRUN_REQ_ACCEPT;
}

static u64 moqtrun_subscribe_refusal_tail(
    const wired_moqt_hub* hub, const moqctl_subscribe* m) {
  u64 code = moqtrun_params_refusal(&m->params);
  if (code != MOQTRUN_REQ_ACCEPT) return code;
  return moqtrun_subscribe_refused(hub, m, &code) ? code : MOQTRUN_REQ_ACCEPT;
}

/* Reserved namespaces first (2.4.2/2.4.3), then parameters and
 * authorization. */
static u64 moqtrun_subscribe_refusal(
    const wired_moqt_hub* hub, const moqctl_subscribe* m) {
  if (moqtrun_ns_reserved(&m->name.ns)) return MOQCTL_ERR_DOES_NOT_EXIST;
  return moqtrun_subscribe_refusal_tail(hub, m);
}

/* draft SS10.6 SUBSCRIBE: reject a non-zero SUBGROUP_DELIVERY_TIMEOUT
 * (moqtrun_param_is_nonzero_timeout) and unauthorized subscribers, else
 * delegate matching + response to moqtrun_route_subscribe. */
static void moqtrun_subscribe_checked(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m) {
  u64 code = moqtrun_subscribe_refusal(hub, m);
  if (code != MOQTRUN_REQ_ACCEPT) {
    moqtrun_send_request_error(p, code);
    return;
  }
  moqtrun_route_subscribe(hub, p, peer_idx, m);
}

static void moqtrun_handle_subscribe(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  usz              off = 0;
  moqctl_subscribe m;
  if (moqctl_subscribe_take(p->ver, body, &off, &m) != MOQCTL_OK) return;
  moqtrun_subscribe_checked(hub, p, peer_idx, &m);
}

/* ===================== FETCH (draft 10.12, 10.13, 11.4.4) =============== */

/* The Location right after l. */
static moqctl_loc moqtrun_after(moqctl_loc l) {
  return moqctl_loc_of(l.group, l.object + 1);
}

/* An inclusive end (moqfetch_req_end; Object MOQFETCH_OBJ_GROUP_END = the
 * whole group) as an exclusive bound: the draft-19 End Location "last
 * Object + 1", whose Object 0 means the whole group (10.12.1). */
static moqctl_loc moqtrun_end_excl(moqctl_loc incl) {
  moqctl_loc e = moqfetch_end19_wire(incl);
  return e.object ? e : moqctl_loc_of(e.group + 1, 0);
}

/* A FETCH resolved against its track: the cache records to read, the
 * range [start, end), and the End Location FETCH_OK reports, inclusive
 * (moqfetch_req_end; Object MOQFETCH_OBJ_GROUP_END = a whole group). */
typedef struct {
  u64        tag;
  moqctl_loc start;
  moqctl_loc end;
  moqctl_loc ok_end;
} moqtrun_frange;

static int moqtrun_fetch_live(const wired_moqtrun_fetch* f) {
  return f->in_use;
}

static wired_moqtrun_fetch* moqtrun_fetch_arr_slot(wired_moqtrun_fetch* arr) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++)
    if (!moqtrun_fetch_live(&arr[i])) return &arr[i];
  return 0;
}

static wired_moqtrun_fetch* moqtrun_fetch_slot(wired_moqt_hub* hub) {
  return moqtrun_fetch_arr_slot(hub->fetches);
}

static int moqtrun_fetch_done(const wired_moqtrun_fetch* f) {
  return !moqctl_loc_less(f->cursor, f->end);
}

/* The FETCH_HEADER stream (11.4.4); a range with nothing to serve is the
 * header alone, closed at once (10.12.3). */
static i64 moqtrun_fetch_open_io(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f, wired_span hdr) {
  return moqtrun_fetch_done(f) ? hub->io.send_uni(f->wt, hdr)
                               : hub->io.open_uni_stream(f->wt, hdr);
}

static void moqtrun_fill_opened(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f);

/* 1 once f's stream is open; a refused open retries on the next tick. */
static int moqtrun_fetch_open(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  u8  hdr[16]; /* Type 0x5 + a Request ID varint */
  usz n = 0;
  if (f->opened) return 1;
  moqfetch_hdr_put(wired_mspan_of(hdr, sizeof hdr), &n, f->request_id);
  i64 sid = moqtrun_fetch_open_io(hub, f, wired_span_of(hdr, n));
  if (sid < 0) return 0;
  f->stream_id  = (u64)sid;
  f->opened     = 1;
  f->last_ok_ms = hub->live.last_now_ms;
  f->in_use     = !moqtrun_fetch_done(f);
  moqtrun_fill_opened(hub, f);
  return 1;
}

static int moqtrun_fetch_new_group(const moqfetch_seq* s, u64 group) {
  return !s->have_loc || s->group != group;
}

/* A miss on a fill is End of Timed-Out Range (the hub could not keep the
 * backlog, SS11.4.1); on a plain FETCH it stays End of Unknown Range. */
static u64 moqtrun_fetch_eor(const wired_moqtrun_fetch* f) {
  return f->is_fill ? MOQFETCH_EOR_TIMED_OUT : MOQFETCH_EOR_UNKNOWN;
}

/* A cache item as a fetch Object (11.4.4.1): Object ID Delta and
 * Publisher Priority always present (the cache keeps no priority, so the
 * 12.4 default 128), Group ID Delta when the group changes, Subgroup ID
 * zero. An unknown range is an End of Range marker, eor (11.4.4.2). */
static void moqtrun_fetch_obj_of(
    moqfetch_obj* o, const moqcache_item* it, const moqfetch_seq* s, u64 eor) {
  bytes_memset(o, 0, sizeof *o);
  o->group  = it->loc.group;
  o->object = it->loc.object;
  o->flags  = eor;
  if (it->unknown) return;
  o->flags = MOQFETCH_F_OBJECT | MOQFETCH_F_PRIORITY |
             (moqtrun_fetch_new_group(s, it->loc.group) ? MOQFETCH_F_GROUP : 0);
  o->has_subgroup = 1;
  o->priority     = 128;
  o->payload      = it->payload;
}

/* One serving window: the whole range of an ascending fetch, a single
 * group's slice of a Group Order Descending fill. */
typedef struct {
  moqctl_loc cursor;
  moqctl_loc end;
} moqtrun_fwin;

static int moqtrun_fwin_drained(const moqtrun_fwin* w) {
  return !moqctl_loc_less(w->cursor, w->end);
}

/* The Group a window's exclusive end lies in. */
static u64 moqtrun_fwin_group(const moqtrun_fwin* w) {
  return w->end.object ? w->end.group : w->end.group - 1;
}

/* w moved one group down (11.4.4.1 Descending), clipped to lo. */
static void moqtrun_fwin_down(
    const wired_moqt_hub* hub, u64 tag, moqctl_loc lo, moqtrun_fwin* w) {
  u64        g    = moqtrun_fwin_group(w) - 1;
  moqctl_loc from = g == lo.group ? lo : moqctl_loc_of(g, 0);
  w->end          = moqctl_loc_of(g + 1, 0);
  w->cursor       = moqcache_skip(&hub->cache, tag, from, w->end);
}

/* 1 while a drained descending window still has lower groups to serve. */
static int moqtrun_fwin_more(
    const wired_moqtrun_fetch* f, const moqtrun_fwin* w) {
  return f->descending && moqtrun_fwin_drained(w) &&
         moqtrun_fwin_group(w) != f->lo.group;
}

/* f's serving state once the item ending at from is out: the cursor
 * skipped within the window, a descending fill stepped down past any
 * group with nothing to serve. Drained = the fetch is over (FIN). */
static void moqtrun_fetch_after(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_fetch* f,
    moqctl_loc                 from,
    moqtrun_fwin*              w) {
  w->end    = f->end;
  w->cursor = moqcache_skip(&hub->cache, f->cache_tag, from, w->end);
  while (moqtrun_fwin_more(f, w))
    moqtrun_fwin_down(hub, f->cache_tag, f->lo, w);
}

/* Sends the item at f's cursor (FIN on the last); 0 when the transport
 * refused it -- the cursor stays and the item is looked up afresh on the
 * next try. relay_scratch is free here (its doc). */
static int moqtrun_fetch_send_one(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  moqcache_item it;
  moqfetch_obj  o;
  moqtrun_fwin  w;
  moqfetch_seq  seq = f->seq;
  usz           n   = 0;
  moqcache_item_at(&hub->cache, f->cache_tag, f->cursor, f->end, &it);
  moqtrun_fetch_obj_of(&o, &it, &seq, moqtrun_fetch_eor(f));
  moqfetch_obj_put(
      wired_mspan_of(hub->relay_scratch, sizeof hub->relay_scratch), &n, &seq,
      &o);
  moqtrun_fetch_after(hub, f, it.next, &w);
  int fin = moqtrun_fwin_drained(&w);
  if (hub->io.stream_send(
          f->wt, f->stream_id, wired_span_of(hub->relay_scratch, n), fin) <= 0)
    return 0;
  f->seq        = seq;
  f->cursor     = w.cursor;
  f->end        = w.end;
  f->in_use     = !fin;
  f->last_ok_ms = hub->live.last_now_ms;
  return 1;
}

static void moqtrun_fetch_pump(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  while (f->in_use && moqtrun_fetch_send_one(hub, f)) {
  }
}

/* Serves f until it ends or the transport refuses a round. */
static void moqtrun_fetch_serve(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  if (moqtrun_fetch_open(hub, f)) moqtrun_fetch_pump(hub, f);
}

/* Ends f early: its data stream is reset with code and the slot freed. */
static void moqtrun_fetch_stop_code(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, u32 code) {
  if (f->opened) hub->io.stream_reset(f->wt, f->stream_id, code);
  f->in_use = 0;
}

/* Cancelled by its requester (3.3.4 CANCELLED). */
static void moqtrun_fetch_stop(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  moqtrun_fetch_stop_code(hub, f, MOQTRUN_RESET_CANCELLED);
}

/* A fill held unopened (the transport refused the uni stream): kept
 * silently -- no reset, no give-up -- until credit arrives or its
 * subscription is cancelled (SS9.20.15). */
static int moqtrun_fetch_blocked(const wired_moqtrun_fetch* f) {
  return f->is_fill && !f->opened;
}

static int moqtrun_fetch_owned(
    const wired_moqtrun_fetch* f, const wired_wt_session* s) {
  return f->in_use && f->wt == s;
}

/* 1 iff f is a held fill of subscription {s, rid}. */
static int moqtrun_fill_held_of(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 rid) {
  return moqtrun_fetch_owned(f, s) && moqtrun_fetch_blocked(f) &&
         f->owner_rid == rid;
}

static int moqtrun_fill_held_in(
    const wired_moqtrun_fetch* arr, const wired_wt_session* s, u64 rid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++)
    if (moqtrun_fill_held_of(&arr[i], s, rid)) return 1;
  return 0;
}

/* 1 iff subscription {s, rid} still has a fill waiting for a stream --
 * refused its uni stream (fetches) or still waiting for a serving slot
 * (fetch_waits). */
static int moqtrun_fill_held_for(
    const wired_moqt_hub* hub, const wired_wt_session* s, u64 rid) {
  return moqtrun_fill_held_in(hub->fetches, s, rid) ||
         moqtrun_fill_held_in(hub->fetch_waits, s, rid);
}

/* Refused for longer than WIRED_MOQTREL_STALL_MS: a peer that stopped
 * reading, so the slot is not held forever. */
static int moqtrun_fetch_stalled(
    const wired_moqt_hub* hub, const wired_moqtrun_fetch* f) {
  return f->in_use && !moqtrun_fetch_blocked(f) &&
         hub->live.last_now_ms - f->last_ok_ms > WIRED_MOQTREL_STALL_MS;
}

/* The stall names its cause: a subscriber that stopped reading its fill
 * is DELIVERY_TIMEOUT (draft-22 names this exact case); an unread FETCH
 * answer stays CANCELLED. */
static u32 moqtrun_fetch_stall_code(const wired_moqtrun_fetch* f) {
  return f->is_fill ? MOQTRUN_RESET_DELIVERY_TIMEOUT : MOQTRUN_RESET_CANCELLED;
}

/* 1 when f failed (its upstream left): an open stream is reset with
 * INTERNAL_ERROR now, a held fill the moment the transport grants one
 * -- opened only to signal the failure (3.3.4). */
static int moqtrun_fetch_fail_due(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  if (!f->failed) return 0;
  if (moqtrun_fetch_open(hub, f))
    moqtrun_fetch_stop_code(hub, f, MOQTRUN_RESET_INTERNAL_ERROR);
  return 1;
}

static void moqtrun_fetch_tick_one(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  if (moqtrun_fetch_fail_due(hub, f)) return;
  moqtrun_fetch_serve(hub, f);
  if (moqtrun_fetch_stalled(hub, f))
    moqtrun_fetch_stop_code(hub, f, moqtrun_fetch_stall_code(f));
}

/* 1 iff f is a live fill serving track incarnation tag. */
static int moqtrun_fill_of_tag(const wired_moqtrun_fetch* f, u64 tag) {
  return f->in_use && f->is_fill && f->cache_tag == tag;
}

/* The upstream publisher of tag left: a fill is a live continuation of
 * its subscription, so it cannot go on (unlike a FETCH of what remains
 * cached). Open fills reset INTERNAL_ERROR now, held ones when opened. */
static void moqtrun_fill_upstream_gone_one(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  f->failed = 1;
  if (f->opened) moqtrun_fetch_stop_code(hub, f, MOQTRUN_RESET_INTERNAL_ERROR);
}

static void moqtrun_fills_tag_gone(
    wired_moqt_hub* hub, wired_moqtrun_fetch* arr, u64 tag) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++)
    if (moqtrun_fill_of_tag(&arr[i], tag))
      moqtrun_fill_upstream_gone_one(hub, &arr[i]);
}

static void moqtrun_fills_upstream_gone(wired_moqt_hub* hub, u64 tag) {
  moqtrun_fills_tag_gone(hub, hub->fetches, tag);
  moqtrun_fills_tag_gone(hub, hub->fetch_waits, tag);
}

/* 1 iff f is served by the tick pass of direction descending. */
static int moqtrun_fetch_in_pass(const wired_moqtrun_fetch* f, int descending) {
  return moqtrun_fetch_live(f) && f->descending == descending;
}

static void moqtrun_fill_waits_tick(wired_moqt_hub* hub, int descending);

/* One serving pass over the fetch table, descending fills only when
 * descending -- ascending backlog goes out before the live rounds of
 * the same tick, a descending one after them (SS9.20.15: catch-up
 * precedes live only while it serves the Objects right behind it).
 * Waiting fills move into freed slots first, so they serve this pass. */
static void moqtrun_fetches_tick(wired_moqt_hub* hub, int descending) {
  moqtrun_fill_waits_tick(hub, descending);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++)
    if (moqtrun_fetch_in_pass(&hub->fetches[i], descending))
      moqtrun_fetch_tick_one(hub, &hub->fetches[i]);
}

/* 1 iff f answers request rid, or is a fill owned by subscription rid
 * (a REQUEST_UPDATE's fill carries its own request_id but dies with the
 * subscription, SS9.20.15). */
static int moqtrun_fetch_under(const wired_moqtrun_fetch* f, u64 rid) {
  return f->request_id == rid || (f->is_fill && f->owner_rid == rid);
}

static int moqtrun_fetch_is_req(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 rid) {
  return moqtrun_fetch_owned(f, s) && moqtrun_fetch_under(f, rid);
}

static void moqtrun_fetch_arr_cancel(
    wired_moqt_hub*         hub,
    wired_moqtrun_fetch*    arr,
    const wired_wt_session* s,
    u64                     rid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++)
    if (moqtrun_fetch_is_req(&arr[i], s, rid)) moqtrun_fetch_stop(hub, &arr[i]);
}

/* The FETCH request rid of s was cancelled (3.3.3): its fetch stops,
 * and a fill of rid still waiting for a serving slot is dropped without
 * ever opening (the cancel is a held fill's only other exit). */
static void moqtrun_fetches_cancel(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 rid) {
  moqtrun_fetch_arr_cancel(hub, hub->fetches, s, rid);
  moqtrun_fetch_arr_cancel(hub, hub->fetch_waits, s, rid);
}

static int moqtrun_fetch_on_stream(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 sid) {
  return moqtrun_fetch_owned(f, s) && f->opened && f->stream_id == sid;
}

/* The peer stopped (or reset) s's fetch data stream sid: nothing more
 * can be sent on it, so its slot is freed. */
static void moqtrun_fetches_stream_gone(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++)
    if (moqtrun_fetch_on_stream(&hub->fetches[i], s, sid))
      hub->fetches[i].in_use = 0;
}

static int moqtrun_encode_fetch_ok(wired_mspan buf, usz* off, const void* m) {
  return moqfetch_ok_encode(buf, off, m);
}

static int moqtrun_encode_fetch_ok19(wired_mspan buf, usz* off, const void* m) {
  return moqfetch_ok19_encode(buf, off, m);
}

/* End Location on the wire: inclusive in draft-22 (SS9.12), last + 1 with
 * Object 0 = whole group before (10.13). */
static moqtrun_body_encode_fn moqtrun_fetch_ok_encoder(int ver) {
  return (moqver_caps(ver) & MOQVER_CAP_FETCH_END_INCLUSIVE)
             ? moqtrun_encode_fetch_ok
             : moqtrun_encode_fetch_ok19;
}

/* FETCH_OK (10.13): not End Of Track, End Location end (inclusive), no
 * parameters or Track Properties. */
static void moqtrun_queue_fetch_ok(wired_moqtrun_peer* p, moqctl_loc end) {
  u8          msg[WIRED_MOQTRUN_CTL_REPLY_MAX];
  moqfetch_ok ok = {0};
  ok.end         = end;
  usz n          = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQFETCH_T_FETCH_OK,
      moqtrun_fetch_ok_encoder(p->ver), &ok);
  moqtrun_queue_reply(p, wired_span_of(msg, n));
}

/* The Location of the last item r serves (its End Location when it serves
 * none). ponytail: walks the cache once per FETCH_OK -- O(arena), like
 * every moqcache lookup. */
static moqctl_loc moqtrun_fetch_last(
    const moqcache* c, const moqtrun_frange* r) {
  moqctl_loc    last = r->ok_end;
  moqcache_item it;
  for (moqctl_loc cur = moqcache_skip(c, r->tag, r->start, r->end);
       moqctl_loc_less(cur, r->end);
       cur = moqcache_skip(c, r->tag, it.next, r->end)) {
    moqcache_item_at(c, r->tag, cur, r->end, &it);
    last = it.loc;
  }
  return last;
}

/* draft-22 has no "whole group" End Location: a range ending at a whole
 * group that Largest did not cut reports the last Object it returns. */
static int moqtrun_fetch_end_open22(
    const wired_moqtrun_peer* p, const moqtrun_frange* r) {
  return (moqver_caps(p->ver) & MOQVER_CAP_FETCH_END_INCLUSIVE) &&
         r->ok_end.object == MOQFETCH_OBJ_GROUP_END;
}

static moqctl_loc moqtrun_fetch_ok_end(
    const wired_moqt_hub*     hub,
    const wired_moqtrun_peer* p,
    const moqtrun_frange*     r) {
  if (!moqtrun_fetch_end_open22(p, r)) return r->ok_end;
  return moqtrun_fetch_last(&hub->cache, r);
}

/* Claims a fetch slot serving r to wt under request_id, its cursor on
 * the first cached item; 0 when the table is full. */
static wired_moqtrun_fetch* moqtrun_fetch_begin(
    wired_moqt_hub*       hub,
    wired_wt_session*     wt,
    u64                   request_id,
    const moqtrun_frange* r) {
  wired_moqtrun_fetch* f = moqtrun_fetch_slot(hub);
  if (!f) return 0;
  bytes_memset(f, 0, sizeof *f);
  f->in_use     = 1;
  f->wt         = wt;
  f->request_id = request_id;
  f->cache_tag  = r->tag;
  f->end        = r->end;
  f->cursor     = moqcache_skip(&hub->cache, r->tag, r->start, r->end);
  f->last_ok_ms = hub->live.last_now_ms;
  return f;
}

static void moqtrun_fetch_descend(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, const moqtrun_frange* r);

/* GROUP_ORDER 0x2 (10.2.8): the fetch's groups go out newest first. */
static int moqtrun_fetch_order_desc(const moqctl_params* params) {
  const moqctl_param* g = moqctl_params_find(params, MOQCTL_PARAM_GROUP_ORDER);
  return g != 0 && g->u8v == 0x2;
}

/* Answers FETCH_OK and starts serving r from the cache, by descending
 * Group when the FETCH asked for it. */
static void moqtrun_fetch_accept(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    u64                   request_id,
    const moqtrun_frange* r,
    int                   descending) {
  wired_moqtrun_fetch* f = moqtrun_fetch_begin(hub, p->wt, request_id, r);
  if (!f) {
    moqtrun_send_request_error(p, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  f->seq.eor_timed_out =
      (moqver_caps(p->ver) & MOQVER_CAP_EOR_TIMED_OUT) != 0; /* 22 SS11.4.1 */
  if (descending) moqtrun_fetch_descend(hub, f, r);
  moqtrun_queue_fetch_ok(p, moqtrun_fetch_ok_end(hub, p, r));
  moqtrun_fetch_serve(hub, f);
}

/* 10.12.3 INVALID_RANGE: nothing published, Start past the Largest
 * Object, or End not past Start. */
static int moqtrun_fetch_range_bad(
    const wired_moqtrun_track* t, moqctl_loc start, moqctl_loc end) {
  return !t->has_largest || moqctl_loc_less(t->largest, start) ||
         !moqctl_loc_less(start, end);
}

/* 10.13: an End (inclusive) past the Largest Object is cut to the Largest
 * Object, and FETCH_OK says so. */
static void moqtrun_fetch_clamp(
    moqtrun_frange* r, const wired_moqtrun_track* t, moqctl_loc end) {
  moqctl_loc top = moqtrun_after(t->largest);
  r->end         = moqtrun_end_excl(end);
  r->ok_end      = end;
  if (!moqctl_loc_less(top, r->end)) return;
  r->end    = top;
  r->ok_end = t->largest;
}

/* rl resolved against t into r; 0 when the range is INVALID_RANGE
 * (10.12.3). */
static int moqtrun_fetch_resolve(
    const wired_moqtrun_track* t,
    const moqctl_rangeloc*     rl,
    moqtrun_frange*            r) {
  moqctl_loc start, end;
  if (rl->sk == MOQCTL_RSK_NEXT_OBJ) return 0; /* always past Largest */
  start = MOQTRUN_START_FNS[rl->sk](moqtrun_track_top(t), rl);
  end   = moqfetch_req_end(rl, t->largest);
  if (moqtrun_fetch_range_bad(t, start, moqtrun_end_excl(end))) return 0;
  r->tag   = t->cache_tag;
  r->start = start;
  moqtrun_fetch_clamp(r, t, end);
  return 1;
}

/* A Standalone Fetch (draft-19 10.12.1; every draft-22 FETCH) of a
 * peer-published track. */
static void moqtrun_fetch_standalone(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqfetch_req* m) {
  u8                   ns_buf[WIRED_MOQTRUN_MAX_NS];
  moqtrun_frange       r;
  wired_moqtrun_track* t =
      moqtrun_find_published_track(hub, moqtrun_key_of(&m->track, ns_buf));
  if (!t) {
    moqtrun_send_request_error(p, MOQCTL_ERR_DOES_NOT_EXIST);
    return;
  }
  if (!moqtrun_fetch_resolve(t, &m->range, &r)) {
    moqtrun_send_request_error(p, MOQCTL_ERR_INVALID_RANGE);
    return;
  }
  moqtrun_fetch_accept(
      hub, p, m->request_id, &r, moqtrun_fetch_order_desc(&m->params));
}

/* ============ fill fetch streams (draft-22 SS9.20.15) ============ */

/* Rewinds f to serve r by descending Group (Objects within a group stay
 * ascending, 11.4.4.1): its window becomes the top group's slice of r,
 * stepped down past groups with nothing to serve. */
static void moqtrun_fetch_descend(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, const moqtrun_frange* r) {
  moqtrun_fwin w    = {r->start, r->end};
  u64          g    = moqtrun_fwin_group(&w);
  f->descending     = 1;
  f->seq.descending = 1;
  f->lo             = r->start;
  moqtrun_fetch_after(
      hub, f, g == r->start.group ? r->start : moqctl_loc_of(g, 0), &w);
  f->cursor = w.cursor;
  f->end    = w.end;
}

/* f marked as the fill of the subscription owner_rid, serving under its
 * own FETCH_HEADER Request ID: fills exist on draft-22 only, so 0x20C is
 * legal on the stream (SS11.4.1), and a Descending GROUP_ORDER rewinds
 * it to the range's top group. */
static void moqtrun_fill_flag(
    wired_moqt_hub*       hub,
    wired_moqtrun_fetch*  f,
    u64                   owner_rid,
    int                   descending,
    const moqtrun_frange* r) {
  f->is_fill           = 1;
  f->owner_rid         = owner_rid;
  f->seq.eor_timed_out = 1;
  if (descending) moqtrun_fetch_descend(hub, f, r);
}

/* Holds a fill the full fetch table cannot serve yet (SS9.20.15: held
 * unopened, never silently dropped -- the exits are a freed slot and
 * the owner's cancel). Counted into the Stream Count now: PUBLISH_DONE
 * waits for it, so the count is right by the time it goes out.
 * ponytail: both tables full still drops the fill; widen fetch_waits if
 * a real room ever queues past WIRED_MOQTRUN_MAX_FETCHES held fills. */
static void moqtrun_fill_wait_put(
    wired_moqt_hub*       hub,
    wired_wt_session*     wt,
    u64                   rid,
    wired_moqtrun_sub*    sub,
    const moqtrun_frange* r,
    int                   descending) {
  wired_moqtrun_fetch* w = moqtrun_fetch_arr_slot(hub->fetch_waits);
  if (!w) return;
  bytes_memset(w, 0, sizeof *w);
  w->in_use     = 1;
  w->is_fill    = 1;
  w->wt         = wt;
  w->request_id = rid;
  w->owner_rid  = sub->request_id;
  w->cache_tag  = r->tag;
  w->cursor     = r->start;
  w->end        = r->end;
  w->descending = descending;
  sub->stream_count++;
}

/* A waiting fill whose serving slot came free: taken over by fetches[]
 * and the normal open/serve path -- or open-to-reset, for one whose
 * upstream left while it waited -- continues from there. */
static void moqtrun_fill_wait_convert(
    wired_moqt_hub* hub, wired_moqtrun_fetch* w) {
  moqtrun_frange       r = {w->cache_tag, w->cursor, w->end, {0, 0}};
  wired_moqtrun_fetch* f = moqtrun_fetch_begin(hub, w->wt, w->request_id, &r);
  if (!f) return;
  moqtrun_fill_flag(hub, f, w->owner_rid, w->descending, &r);
  f->failed = w->failed;
  w->in_use = 0;
}

static void moqtrun_fill_waits_tick(wired_moqt_hub* hub, int descending) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++)
    if (moqtrun_fetch_in_pass(&hub->fetch_waits[i], descending))
      moqtrun_fill_wait_convert(hub, &hub->fetch_waits[i]);
}

/* The fill's LOCATION_FILTER as a FETCH range: no filter fills
 * everything up to the Largest Object (SS9.20.9). */
static moqctl_rangeloc moqtrun_fill_rl(const moqfetch_fill* fill) {
  moqctl_rangeloc all = {MOQCTL_RSK_ABS, 0, 0, MOQCTL_REK_UNBOUNDED, 0, 0};
  return fill->has_filter ? fill->range : all;
}

/* Opens one fill fetch stream over track's cached range for the
 * subscription owning sub; rid is the FETCH_HEADER's Request ID (the
 * SUBSCRIBE's or REQUEST_UPDATE's that carried FILL_PARAMETERS). A range
 * starting past the Largest Object -- or an empty track -- opens
 * nothing; an end past it is cut to it. */
static void moqtrun_fill_open(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_peer*  p,
    wired_moqtrun_sub*   sub,
    u64                  rid,
    const moqfetch_fill* fill) {
  moqtrun_frange  r;
  moqctl_rangeloc rl = moqtrun_fill_rl(fill);
  if (!moqtrun_fetch_resolve(track, &rl, &r)) return;
  wired_moqtrun_fetch* f = moqtrun_fetch_begin(hub, p->wt, rid, &r);
  if (!f) {
    moqtrun_fill_wait_put(hub, p->wt, rid, sub, &r, fill->descending);
    return;
  }
  sub->stream_count++; /* PUBLISH_DONE counts fills too (10.10) */
  moqtrun_fill_flag(hub, f, sub->request_id, fill->descending, &r);
  moqtrun_fetch_serve(hub, f);
}

/* A FILL_PARAMETERS parameter asks for a fill only while the
 * subscription forwards (SS9.20.15; FORWARD 0 holds everything). */
static int moqtrun_fill_requested(
    const moqctl_param* fp, const wired_moqtrun_sub* sub) {
  return fp != 0 && !sub->forward_off;
}

/* Decodes fp's FILL_PARAMETERS value and opens the fill under rid;
 * nothing without the parameter, on a FORWARD-0 subscription, or on a
 * malformed value. */
static void moqtrun_fill_from_param(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* track,
    wired_moqtrun_sub*   sub,
    u64                  rid,
    const moqctl_param*  fp) {
  moqfetch_fill fill;
  if (!moqtrun_fill_requested(fp, sub)) return;
  if (moqfetch_fill_take(fp->bytes, &fill) != MOQCTL_OK) return;
  moqtrun_fill_open(hub, track, p, sub, rid, &fill);
}

/* FILL_PARAMETERS on an accepted SUBSCRIBE: the fill rides the
 * SUBSCRIBE's own Request ID. */
static void moqtrun_fill_on_subscribe(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* track,
    wired_moqtrun_sub*   sub,
    const moqctl_params* params) {
  moqtrun_fill_from_param(
      hub, p, track, sub, sub->request_id,
      moqctl_params_find(params, MOQCTL_PARAM_FILL_PARAMETERS));
}

/* FILL_PARAMETERS on an applied REQUEST_UPDATE: the new fill's
 * FETCH_HEADER carries the update's own Request ID (draft-22 9.8), an
 * earlier fill keeps running beside it. Only a live track is filled --
 * state kept for a gone publisher has no cache to read. */
static void moqtrun_fill_on_update(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* track,
    wired_moqtrun_sub*   sub,
    const moqctl_params* params,
    u64                  rid) {
  if (!track) return;
  moqtrun_fill_from_param(
      hub, p, track, sub, rid,
      moqctl_params_find(params, MOQCTL_PARAM_FILL_PARAMETERS));
}

static int moqtrun_sub_has_rid(const wired_moqtrun_sub* s, usz idx, u64 rid) {
  return moqtrun_sub_is_peer(s, idx) && s->request_id == rid;
}

static wired_moqtrun_sub* moqtrun_track_sub_by_rid(
    wired_moqtrun_track* t, usz idx, u64 rid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (moqtrun_sub_has_rid(&t->subs[i], idx, rid)) return &t->subs[i];
  return 0;
}

/* t's subscription for (idx, rid) while t is published, else 0. */
static wired_moqtrun_sub* moqtrun_live_track_sub_by_rid(
    wired_moqtrun_track* t, usz idx, u64 rid) {
  return t->in_use ? moqtrun_track_sub_by_rid(t, idx, rid) : 0;
}

static wired_moqtrun_sub* moqtrun_peer_sub_by_rid(
    wired_moqtrun_peer* q, usz idx, u64 rid, wired_moqtrun_track** t) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; i++) {
    *t                   = &q->tracks[i];
    wired_moqtrun_sub* s = moqtrun_live_track_sub_by_rid(*t, idx, rid);
    if (s) return s;
  }
  return 0;
}

static wired_moqtrun_sub* moqtrun_live_peer_sub_by_rid(
    wired_moqtrun_peer* q, usz idx, u64 rid, wired_moqtrun_track** t) {
  return q->in_use ? moqtrun_peer_sub_by_rid(q, idx, rid, t) : 0;
}

/* Peer idx's subscription with Request ID rid on a peer track (*t).
 * Peer tracks only: the hub's own blob and live tracks are never cached,
 * so they are no Joining Fetch target (nor a Standalone one --
 * moqtrun_find_published_track also looks at peer tracks only). */
static wired_moqtrun_sub* moqtrun_sub_by_rid(
    wired_moqt_hub* hub, usz idx, u64 rid, wired_moqtrun_track** t) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    wired_moqtrun_sub* s =
        moqtrun_live_peer_sub_by_rid(&hub->peers[i], idx, rid, t);
    if (s) return s;
  }
  return 0;
}

/* 10.12.2.1 Start group: Joining Location.Group - Joining Start (never
 * below 0) for a Relative, Joining Start itself for an Absolute Joining
 * Fetch. */
static u64 moqtrun_join_group(const moqfetch_req* m, moqctl_loc jl) {
  if (m->fetch_type == MOQFETCH_ABSOLUTE_JOINING) return m->joining_start;
  return jl.group - u64_min(m->joining_start, jl.group);
}

/* 10.12.2 INVALID_RANGE: no Joining Location (nothing was published at
 * SUBSCRIBE_OK), Forward State 0, or a Start past the Joining Location. */
static int moqtrun_join_bad(const wired_moqtrun_sub* s, u64 group) {
  return !s->has_jl || s->forward_off || group > s->jl.group;
}

/* 10.12.2 Joining Fetch: ends at the subscription's Joining Location so
 * FETCH and SUBSCRIBE meet with no gap or overlap. */
static void moqtrun_fetch_joining(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    usz                 peer_idx,
    const moqfetch_req* m) {
  wired_moqtrun_track* t = 0;
  wired_moqtrun_sub*   s =
      moqtrun_sub_by_rid(hub, peer_idx, m->joining_request_id, &t);
  moqtrun_frange r;
  if (!s) {
    moqtrun_send_request_error(p, MOQFETCH_ERR_INVALID_JOINING_REQUEST_ID);
    return;
  }
  u64 group = moqtrun_join_group(m, s->jl);
  if (moqtrun_join_bad(s, group)) {
    moqtrun_send_request_error(p, MOQCTL_ERR_INVALID_RANGE);
    return;
  }
  r.tag    = t->cache_tag;
  r.start  = moqctl_loc_of(group, 0);
  r.end    = moqtrun_after(s->jl);
  r.ok_end = s->jl;
  moqtrun_fetch_accept(
      hub, p, m->request_id, &r, moqtrun_fetch_order_desc(&m->params));
}

/* The FETCH body in p's draft: draft-22's (SS9.11) or the draft-18/19
 * one (10.12), both into moqfetch_req. */
static int moqtrun_fetch_take(
    const wired_moqtrun_peer* p, wired_span body, moqfetch_req* m) {
  if (moqver_caps(p->ver) & MOQVER_CAP_FETCH_BODY_V22)
    return moqfetch_req22_take(body, m);
  return moqfetch_req19_take(p->ver, body, m);
}

static void moqtrun_close_with(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u32 code);

/* The decoded FETCH m routed by kind. draft-22 dropped the Joining Fetch
 * (SS9.11 names one Fetch shape only), so a session on the draft-22 body
 * presenting the Joining structure closes with PROTOCOL_VIOLATION. */
static void moqtrun_fetch_route(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    usz                 peer_idx,
    const moqfetch_req* m) {
  if (!m->is_joining) {
    moqtrun_fetch_standalone(hub, p, m);
    return;
  }
  if (moqver_caps(p->ver) & MOQVER_CAP_FETCH_BODY_V22) {
    moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
    return;
  }
  moqtrun_fetch_joining(hub, p, peer_idx, m);
}

/* draft 10.12 FETCH. A body that fails to decode is a malformed control
 * message: the session closes, like a malformed REQUEST_UPDATE. */
static void moqtrun_handle_fetch(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  moqfetch_req m;
  if (moqtrun_fetch_take(p, body, &m) != MOQCTL_OK) {
    moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
    return;
  }
  if (moqtrun_rngf_refusal(&m.params) != MOQTRUN_REQ_ACCEPT) {
    moqtrun_send_request_error(p, MOQCTL_ERR_INVALID_FILTER);
    return;
  }
  moqtrun_fetch_route(hub, p, peer_idx, &m);
}

static void moqtrun_fetch_arr_drop(
    wired_moqtrun_fetch* arr, const wired_wt_session* s) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++)
    if (arr[i].wt == s) arr[i].in_use = 0;
}

/* A closed session's fetches end: nothing more is sent for them. */
static void moqtrun_fetches_drop(wired_moqt_hub* hub, wired_wt_session* s) {
  moqtrun_fetch_arr_drop(hub->fetches, s);
  moqtrun_fetch_arr_drop(hub->fetch_waits, s);
}

/* ===================== TRACK_STATUS (draft 10.14) ===================== */

/* The track a SUBSCRIBE for f would reach (moqtrun_route_subscribe's
 * order: the hub's own tracks first), else 0. */
static wired_moqtrun_track* moqtrun_tstat_track(
    wired_moqt_hub* hub, const moqctl_ftn* f) {
  u8 ns_buf[WIRED_MOQTRUN_MAX_NS];
  if (moqtrun_track_name_matches(&hub->blob_track, f->name))
    return &hub->blob_track;
  if (moqtrun_track_name_matches(&hub->live.track, f->name))
    return &hub->live.track;
  return moqtrun_find_published_track(hub, moqtrun_key_of(f, ns_buf));
}

/* Treated as a SUBSCRIBE that creates no state and sends no Objects:
 * TRACK_STATUS_OK carries what SUBSCRIBE_OK would (the Largest Location),
 * and the request, answered without going live, is FINed. */
static u64 moqtrun_tstat_verdict(
    const wired_moqt_hub*      hub,
    const moqctl_subscribe*    m,
    const wired_moqtrun_track* t) {
  u64 code = MOQCTL_ERR_DOES_NOT_EXIST;
  if (!t) return code;
  if (moqtrun_subscribe_refused(hub, m, &code)) return code;
  return MOQTRUN_REQ_ACCEPT;
}

static void moqtrun_tstat_answer(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_span body) {
  moqctl_subscribe m;
  if (moqtstat_take(p->ver, body, &m) != MOQCTL_OK) return;
  wired_moqtrun_track* t    = moqtrun_tstat_track(hub, &m.name);
  u64                  code = moqtrun_tstat_verdict(hub, &m, t);
  if (code != MOQTRUN_REQ_ACCEPT) {
    moqtrun_send_request_error(p, code);
    return;
  }
  moqtrun_queue_request_ok(p, t);
}

/* TRACK_STATUS is the first and only message of a new request stream
 * (10.14): on the control stream it is NOT_SUPPORTED, like the namespace
 * requests. */
static void moqtrun_handle_tstat(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)peer_idx;
  if (!p->req) {
    moqtrun_send_request_error(p, MOQCTL_ERR_NOT_SUPPORTED);
    return;
  }
  moqtrun_tstat_answer(hub, p, body);
}

/* ===================== REQUEST_UPDATE (draft 10.9) ===================== */

static void moqtrun_close_with(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u32 code);

/* Peer idx's live subscription rid on any track, *t its track. */
static wired_moqtrun_sub* moqtrun_hub_sub_by_rid(
    wired_moqt_hub* hub, usz idx, u64 rid, wired_moqtrun_track** t) {
  wired_moqtrun_sub* s = moqtrun_sub_by_rid(hub, idx, rid, t);
  if (s) return s;
  *t = &hub->blob_track;
  s  = moqtrun_live_track_sub_by_rid(*t, idx, rid);
  if (s) return s;
  *t = &hub->live.track;
  return moqtrun_live_track_sub_by_rid(*t, idx, rid);
}

/* The state p remembers for subscription rid (sub_names), else 0. */
static wired_moqtrun_sub* moqtrun_sub_state_by_rid(
    wired_moqtrun_peer* p, u64 rid) {
  for (usz i = 0; i < p->sub_names_n; i++)
    if (p->sub_state[i].request_id == rid) return &p->sub_state[i];
  return 0;
}

/* The subscription to update: its live slot (*t its track), else -- its
 * publisher gone -- the state kept for its return (*t 0), else 0. */
static wired_moqtrun_sub* moqtrun_upd_target(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    usz                   idx,
    wired_moqtrun_track** t) {
  wired_moqtrun_sub* s =
      moqtrun_hub_sub_by_rid(hub, idx, p->req->request_id, t);
  if (s) return s;
  *t = 0;
  return moqtrun_sub_state_by_rid(p, p->req->request_id);
}

typedef void (*moqtrun_upd_fn)(
    wired_moqtrun_sub*, const wired_moqtrun_track*, const moqctl_param*);

static void moqtrun_upd_forward(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p) {
  (void)t;
  s->forward_off = moqtrun_forward_off(p);
}

static void moqtrun_upd_priority(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p) {
  (void)t;
  s->priority     = (u8)p->u8v;
  s->has_priority = 1;
}

static void moqtrun_upd_timeout(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p) {
  (void)t;
  s->delivery_timeout     = p->vi;
  s->has_delivery_timeout = 1;
}

static void moqtrun_upd_filter(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p) {
  moqtrun_sub_filter(s, t, p);
}

/* The update's SUBGROUP_DELIVERY_TIMEOUT re-mins against the publisher's
 * Track Property (t 0 while the publisher is away: no property side). */
static void moqtrun_upd_sgt(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p) {
  s->subgroup_timeout =
      moqtrun_timeout_min(t ? t->subgroup_timeout_ms : 0, p->vi);
}

/* Parameters in the update's scope this hub keeps no state for. */
static void moqtrun_upd_ignore(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* p) {
  (void)s;
  (void)t;
  (void)p;
}

static const struct {
  u64            type;
  moqtrun_upd_fn fn;
} moqtrun_upd_table[] = {
    {MOQCTL_PARAM_FORWARD, moqtrun_upd_forward},
    {MOQCTL_PARAM_SUBSCRIBER_PRIORITY, moqtrun_upd_priority},
    {MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT, moqtrun_upd_timeout},
    {MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT, moqtrun_upd_sgt},
    {MOQCTL_PARAM_LOCATION_FILTER, moqtrun_upd_filter},
};

static moqtrun_upd_fn moqtrun_upd_lookup(u64 type) {
  for (usz i = 0; i < sizeof moqtrun_upd_table / sizeof moqtrun_upd_table[0];
       i++)
    if (moqtrun_upd_table[i].type == type) return moqtrun_upd_table[i].fn;
  return moqtrun_upd_ignore;
}

/* FORWARD went 0 -> 1 on a live subscription. */
static int moqtrun_upd_turned_on(
    u8 was_off, const wired_moqtrun_sub* s, const wired_moqtrun_track* t) {
  return was_off && !s->forward_off && t;
}

/* draft 5.1: the Largest Location REQUEST_UPDATE_OK carries becomes the
 * Joining Location; the hub's blob, held back by FORWARD 0, goes out now.
 * 0 when that send is refused. */
static int moqtrun_upd_forward_on(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t) {
  s->jl     = t->largest;
  s->has_jl = (u8)t->has_largest;
  if (t != &hub->blob_track || s->blob_sent) return 1;
  return moqtrun_blob_deliver(hub, p, s);
}

/* Present parameters replace, absent ones stay (10.9). */
static void moqtrun_upd_params(
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params) {
  moqtrun_sub_rngf_update(s, params);
  for (usz i = 0; i < params->n; i++)
    moqtrun_upd_lookup(params->items[i].type)(s, t, &params->items[i]);
}

/* All or nothing: a refused blob send restores the whole subscription as
 * it was and fails the update. */
static int moqtrun_upd_apply(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params) {
  wired_moqtrun_sub before = *s;
  moqtrun_upd_params(s, t, params);
  if (!moqtrun_upd_turned_on(before.forward_off, s, t)) return 1;
  if (moqtrun_upd_forward_on(hub, p, s, t)) return 1;
  *s = before;
  return 0;
}

/* Parameters are refused as on SUBSCRIBE (moqtrun_params_refusal). */
static u64 moqtrun_upd_checked(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params) {
  u64 code = moqtrun_params_refusal(params);
  if (code != MOQTRUN_REQ_ACCEPT) return code;
  return moqtrun_upd_apply(hub, p, s, t, params) ? MOQTRUN_REQ_ACCEPT
                                                 : MOQCTL_ERR_INTERNAL_ERROR;
}

/* The REQUEST_ERROR code for the update, or MOQTRUN_REQ_ACCEPT once it is
 * applied. The concurrent Range Filter total is vetted first (10.4):
 * refused before anything is applied. */
static u64 moqtrun_upd_verdict(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params) {
  if (!s) return MOQCTL_ERR_DOES_NOT_EXIST;
  if (moqtrun_rngf_over(s, params)) return MOQCTL_ERR_INVALID_FILTER;
  return moqtrun_upd_checked(hub, p, s, t, params);
}

/* The updated state is also what a returning publisher re-attaches
 * (moqtrun_reattach_one_sub; only the subscriber changes it, 5.1). */
static void moqtrun_upd_remember(
    wired_moqtrun_peer* p, const wired_moqtrun_sub* s) {
  wired_moqtrun_sub* kept = moqtrun_sub_state_by_rid(p, s->request_id);
  if (kept && kept != s) *kept = *s;
}

static void moqtrun_sub_done(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_req*   q,
    wired_moqtrun_track* t,
    wired_moqtrun_sub*   s,
    u64                  status);

static void moqtrun_update_sub(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    usz                  idx,
    const moqctl_params* params,
    u64                  rid) {
  wired_moqtrun_track* t    = 0;
  wired_moqtrun_sub*   s    = moqtrun_upd_target(hub, p, idx, &t);
  u64                  code = moqtrun_upd_verdict(hub, p, s, t, params);
  if (code != MOQTRUN_REQ_ACCEPT) {
    moqtrun_send_request_error(p, code);
    if (s) moqtrun_sub_done(hub, p, p->req, t, s, MOQCTL_DONE_UPDATE_FAILED);
    return;
  }
  moqtrun_upd_remember(p, s);
  moqtrun_queue_request_ok(p, t);
  moqtrun_fill_on_update(hub, p, t, s, params, rid);
}

static int moqtrun_kind_is_ns(u64 kind) {
  return kind == MOQNS_T_PUBLISH_NAMESPACE ||
         kind == MOQNS_T_SUBSCRIBE_NAMESPACE;
}

/* draft-ietf-moq-transport-19 10.9.1: a failed update of a namespace
 * request closes its bidi stream -- the request ends (a PUBLISH_NAMESPACE
 * is withdrawn, a SUBSCRIBE_NAMESPACE owes no NAMESPACE_DONE any more)
 * and the hub FINs once its answer is out (3.3.2). */
static void moqtrun_upd_close_ns(wired_moqtrun_req* q) {
  if (!q || !moqtrun_kind_is_ns(q->kind)) return;
  q->live    = 0;
  q->ns_seen = 0;
}

static int moqtrun_upd_is_sub(const wired_moqtrun_peer* p) {
  return p->req && p->req->kind == MOQCTL_T_SUBSCRIBE;
}

/* draft-22 9.8 lets the requester also update its own PUBLISH; the
 * earlier drafts keep REQUEST_UPDATE to subscriptions. */
static int moqtrun_upd_is_pub(const wired_moqtrun_peer* p) {
  return p->req && p->req->kind == MOQCTL_T_PUBLISH &&
         (moqver_caps(p->ver) & MOQVER_CAP_UPDATE_ON_PUBLISH);
}

/* draft-ietf-moq-transport-19 10.9: the sender of a FETCH may REQUEST_UPDATE
 * it (e.g. SUBSCRIBER_PRIORITY, 10.2.5). */
static int moqtrun_upd_is_fetch(const wired_moqtrun_peer* p) {
  return p->req && p->req->kind == MOQFETCH_T_FETCH;
}

/* draft-ietf-moq-transport-19 10.9: the sender of a PUBLISH_NAMESPACE or
 * SUBSCRIBE_NAMESPACE may REQUEST_UPDATE it (10.9.1 Updating Namespace
 * Subscriptions covers the latter's TRACK_NAMESPACE_PREFIX). */
static int moqtrun_upd_is_ns(const wired_moqtrun_peer* p) {
  return p->req && moqtrun_kind_is_ns(p->req->kind);
}

/* moqtrun_upd_allowed's non-subscription half, split out to keep each
 * predicate's branch budget small. */
static int moqtrun_upd_is_other(const wired_moqtrun_peer* p) {
  return moqtrun_upd_is_pub(p) || moqtrun_upd_is_fetch(p) ||
         moqtrun_upd_is_ns(p);
}

static int moqtrun_upd_allowed(const wired_moqtrun_peer* p) {
  return moqtrun_upd_is_sub(p) || moqtrun_upd_is_other(p);
}

/* moqtrun_upd_ctx's namespace half: SUBSCRIBE_NAMESPACE vs
 * PUBLISH_NAMESPACE each have their own ctx bit (10.2.x). */
static u32 moqtrun_upd_ns_ctx(const wired_moqtrun_req* q) {
  return q->kind == MOQNS_T_SUBSCRIBE_NAMESPACE
             ? MOQCTL_PCTX_UPDATE_SUBSCRIBE_NAMESPACE
             : MOQCTL_PCTX_UPDATE_PUBLISH_NAMESPACE;
}

/* The MOQCTL_PCTX_UPDATE_* bit a decode must check the update's parameters
 * against, by the request kind riding the stream (10.2.x "MAY appear in"
 * is split the same way). */
static u32 moqtrun_upd_ctx(const wired_moqtrun_peer* p) {
  if (moqtrun_upd_is_fetch(p)) return MOQCTL_PCTX_UPDATE_FETCH;
  if (moqtrun_upd_is_ns(p)) return moqtrun_upd_ns_ctx(p->req);
  return MOQCTL_PCTX_UPDATE_SUBSCRIPTION;
}

/* draft-22 9.8 on a PUBLISH stream: the parameters are vetted as a
 * subscription's would be; the hub models no publisher-side state they
 * would move, so an acceptable update is REQUEST_OK and nothing else. */
static void moqtrun_update_pub(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_params* params) {
  u64 code = moqtrun_params_refusal(params);
  (void)hub;
  if (code != MOQTRUN_REQ_ACCEPT) {
    moqtrun_send_request_error(p, code);
    return;
  }
  moqtrun_queue_request_ok(p, 0);
}

/* MALFORMED_AUTH_TOKEN iff params carries an AUTHORIZATION_TOKEN using an
 * alias (moqtrun_subscribe_refused's twin): this hub's token cache is 0
 * bytes (SS10.3.1.3), the only admitted FETCH-update parameter with a
 * refusal this hub models. */
static u64 moqtrun_fetch_upd_refusal(const moqctl_params* params) {
  return moqtrun_token_uses_alias(moqtrun_auth_token_of(params))
             ? MOQCTL_ERR_MALFORMED_AUTH_TOKEN
             : MOQTRUN_REQ_ACCEPT;
}

/* A REQUEST_UPDATE of a FETCH (10.9, e.g. SUBSCRIBER_PRIORITY 10.2.5):
 * the hub models no other FETCH-serving state the admitted parameters
 * would move, so an acceptable update is REQUEST_OK and nothing else.
 * "When a REQUEST_UPDATE fails for a FETCH, the publisher MUST reset the
 * FETCH data stream" (10.9.1) -- moqtrun_fetches_cancel resets it and
 * frees the hub's own fetch-serving slot. */
static void moqtrun_update_fetch(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_params* params) {
  u64 code = moqtrun_fetch_upd_refusal(params);
  if (code != MOQTRUN_REQ_ACCEPT) {
    moqtrun_send_request_error(p, code);
    moqtrun_fetches_cancel(hub, p->wt, p->req->request_id);
    return;
  }
  moqtrun_queue_request_ok(p, 0);
}

static void moqtrun_update_ns(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_req*   q,
    const moqctl_params* params);

/* moqtrun_update_route_other's FETCH-or-namespace half. 1 iff routed. */
static int moqtrun_update_route_fetch_ns(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_params* params) {
  if (moqtrun_upd_is_fetch(p)) {
    moqtrun_update_fetch(hub, p, params);
    return 1;
  }
  if (moqtrun_upd_is_ns(p)) {
    moqtrun_update_ns(hub, p, p->req, params);
    return 1;
  }
  return 0;
}

/* moqtrun_update_route's non-subscription request kinds (everything but
 * the common-case SUBSCRIBE, kept separate to stay within one function's
 * branch budget). 1 iff p's request matched one and was routed. */
static int moqtrun_update_route_other(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_params* params) {
  if (moqtrun_upd_is_pub(p)) {
    moqtrun_update_pub(hub, p, params);
    return 1;
  }
  return moqtrun_update_route_fetch_ns(hub, p, params);
}

static void moqtrun_update_route(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    usz                  peer_idx,
    const moqctl_params* params,
    u64                  rid) {
  if (moqtrun_update_route_other(hub, p, params)) return;
  moqtrun_update_sub(hub, p, peer_idx, params, rid);
}

/* draft-ietf-moq-transport-19 10.4/10.9: a request stream already
 * holding MAX_REQUEST_UPDATES outstanding (received, not yet answered by
 * a flushed reply) REQUEST_UPDATEs closes the session on one more. */
static int moqtrun_upd_over_credit(const wired_moqtrun_req* q) {
  return q->pending_updates >= WIRED_MOQTRUN_MAX_REQ_UPDATES;
}

/* Rejects (and signals) a REQUEST_UPDATE that must not reach decode: not
 * an allowed request kind, or its stream is already over credit. */
static int moqtrun_upd_refused(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  if (!moqtrun_upd_allowed(p)) {
    moqtrun_send_request_error(p, MOQCTL_ERR_NOT_SUPPORTED);
    moqtrun_upd_close_ns(p->req);
    return 1;
  }
  if (moqtrun_upd_over_credit(p->req)) {
    moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES);
    return 1;
  }
  return 0;
}

/* A REQUEST_UPDATE of the request riding its stream (its own Request ID
 * is a fresh one, 10.1: the stream names the request) -- a SUBSCRIBE, a
 * FETCH, a PUBLISH_NAMESPACE/SUBSCRIBE_NAMESPACE, or (draft-22) the
 * sender's own PUBLISH. On the control stream, or for TRACK_STATUS,
 * NOT_SUPPORTED. A malformed one (e.g. a parameter outside the update's
 * scope for that request kind) closes the session. */
static void moqtrun_handle_update(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  moqtstat_update m;
  if (moqtrun_upd_refused(hub, p)) return;
  if (moqtstat_update_take(p->ver, body, moqtrun_upd_ctx(p), &m) != MOQCTL_OK) {
    moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
    return;
  }
  p->req->pending_updates++;
  moqtrun_update_route(hub, p, peer_idx, &m.params, m.request_id);
}

/* ===================== namespace discovery ===================== */

/* draft-ietf-moq-transport-19 6.1-6.2, 10.15-10.18. A PUBLISH_NAMESPACE
 * or SUBSCRIBE_NAMESPACE lives in its request-stream slot (namespace in
 * wired_moqtrun_req.ns) until cancelled or its session ends, so the
 * per-session request cap bounds both. Hub-owned tracks
 * (wired_moqt_publish_blob/live) carry no namespace and PUBLISH alone
 * (no PUBLISH_NAMESPACE) announces nothing (6.2), so neither appears. */

_Static_assert(WIRED_MOQTRUN_MAX_REQS <= 64, "ns_seen holds one bit per req");

static int moqtrun_disc_is(const wired_moqtrun_req* q, u64 kind) {
  return q->in_use && q->live && q->kind == kind;
}

/* The fields of an encoded namespace (count + Length-prefixed fields),
 * past its count. */
static wired_span moqtrun_disc_fields_of(wired_span enc, u64* count) {
  usz at = 0;
  moqvi_take(enc, &at, count);
  return wired_span_of(enc.p + at, enc.n - at);
}

static wired_span moqtrun_disc_fields(const wired_moqtrun_req* q, u64* count) {
  return moqtrun_disc_fields_of(wired_span_of(q->ns, q->ns_len), count);
}

/* Fields are Length-prefixed, so a byte prefix of the encoded fields is a
 * whole-field prefix (Namespace Prefix Matching, 9.5). */
static int moqtrun_disc_starts(wired_span pre, wired_span all) {
  return pre.n <= all.n && moqtrun_bytes_eq(pre.p, all.p, pre.n);
}

static int moqtrun_disc_under(
    const wired_moqtrun_req* sub, const wired_moqtrun_req* pub) {
  u64 n;
  return moqtrun_disc_starts(
      moqtrun_disc_fields(sub, &n), moqtrun_disc_fields(pub, &n));
}

/* The first field of q's encoded fields; empty for zero fields. */
static wired_span moqtrun_disc_head(const wired_moqtrun_req* q) {
  u64        n, len = 0;
  usz        at = 0;
  wired_span f  = moqtrun_disc_fields(q, &n);
  moqvi_take(f, &at, &len);
  return wired_span_of(f.p, at + (usz)len);
}

/* 10.18 PREFIX_OVERLAP "shares a common prefix", read strictly: the same
 * session's prefixes overlap when either is empty or their first fields
 * are equal. */
static int moqtrun_disc_overlap(
    const wired_moqtrun_req* a, const wired_moqtrun_req* b) {
  u64 n;
  return a->wt == b->wt &&
         (moqtrun_disc_starts(
              moqtrun_disc_head(a), moqtrun_disc_fields(b, &n)) ||
          moqtrun_disc_starts(
              moqtrun_disc_head(b), moqtrun_disc_fields(a, &n)));
}

static int moqtrun_disc_same(
    const wired_moqtrun_req* a, const wired_moqtrun_req* b) {
  return moqtrun_ns_eq(a->ns, a->ns_len, wired_span_of(b->ns, b->ns_len));
}

typedef int (*moqtrun_disc_rel_fn)(
    const wired_moqtrun_req*, const wired_moqtrun_req*);

/* r itself never counts as a clash against q (an update re-checking an
 * already-live q would otherwise always "overlap" its own unchanged
 * namespace -- moqtrun_disc_pub_check/sub_check are shared by creation,
 * where q is not live yet, and update, where it already is). */
static int moqtrun_disc_rel(
    const wired_moqtrun_req* r,
    const wired_moqtrun_req* q,
    u64                      kind,
    moqtrun_disc_rel_fn      rel) {
  return r != q && moqtrun_disc_is(r, kind) && rel(r, q);
}

/* 1 iff a live request of kind relates to q by rel. */
static int moqtrun_disc_any(
    const wired_moqt_hub*    hub,
    const wired_moqtrun_req* q,
    u64                      kind,
    moqtrun_disc_rel_fn      rel) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    if (moqtrun_disc_rel(&hub->reqs[i], q, kind, rel)) return 1;
  return 0;
}

static int moqtrun_disc_same_session(
    const wired_moqtrun_req* a, const wired_moqtrun_req* b) {
  return a->wt == b->wt && moqtrun_disc_same(a, b);
}

/* A session publishing a namespace it already publishes is refused
 * UNINTERESTED (10.6.2). Other sessions may publish the same namespace
 * (9.3 multiple publishers; 3.6 a client migrating after GOAWAY): it is
 * announced once (moqtrun_disc_sync_new). */
static u64 moqtrun_disc_pub_check(
    const wired_moqt_hub* hub, const wired_moqtrun_req* q) {
  int dup = moqtrun_disc_any(
      hub, q, MOQNS_T_PUBLISH_NAMESPACE, moqtrun_disc_same_session);
  return dup ? MOQCTL_ERR_UNINTERESTED : MOQTRUN_REQ_ACCEPT;
}

static u64 moqtrun_disc_sub_check(
    const wired_moqt_hub* hub, const wired_moqtrun_req* q) {
  int clash = moqtrun_disc_any(
      hub, q, MOQNS_T_SUBSCRIBE_NAMESPACE, moqtrun_disc_overlap);
  return clash ? MOQCTL_ERR_PREFIX_OVERLAP : MOQTRUN_REQ_ACCEPT;
}

typedef u64 (*moqtrun_disc_check_fn)(
    const wired_moqt_hub*, const wired_moqtrun_req*);
typedef int (*moqtrun_disc_take_fn)(int, wired_span, moqns_req*);

/* Copies ns into q; 0 when it exceeds WIRED_MOQTRUN_MAX_NS (refused, never
 * truncated). */
static int moqtrun_disc_record(wired_moqtrun_req* q, const moqctl_ns* ns) {
  usz n    = 0;
  int fits = moqctl_ns_put(wired_mspan_of(q->ns, WIRED_MOQTRUN_MAX_NS), &n, ns);
  q->ns_len = n;
  return fits;
}

/* Writes pfx's namespace into q (replacing its current one), 0 if it
 * fails to decode or does not fit. */
static int moqtrun_upd_ns_write(wired_moqtrun_req* q, const moqctl_param* pfx) {
  moqctl_ns ns;
  usz       at = 0;
  if (moqctl_ns_take(pfx->bytes, &at, &ns) != MOQCTL_OK) return 0;
  return moqtrun_disc_record(q, &ns);
}

/* draft-ietf-moq-transport-19 10.9.1 Updating Namespace Subscriptions: a
 * SUBSCRIBE_NAMESPACE's REQUEST_UPDATE may carry a new
 * TRACK_NAMESPACE_PREFIX; the same overlap restriction as a fresh
 * SUBSCRIBE_NAMESPACE applies (moqtrun_disc_sub_check), checked against
 * the CANDIDATE prefix before it replaces the live one -- a refused
 * update leaves the request's existing prefix (and announcements)
 * untouched. */
static u64 moqtrun_upd_ns_prefix(
    wired_moqt_hub* hub, wired_moqtrun_req* q, const moqctl_param* pfx) {
  wired_moqtrun_req before = *q;
  if (!moqtrun_upd_ns_write(q, pfx)) return MOQCTL_ERR_INTERNAL_ERROR;
  u64 code = moqtrun_disc_sub_check(hub, q);
  if (code == MOQTRUN_REQ_ACCEPT) return code;
  q->ns_len = before.ns_len;
  bytes_memcpy(q->ns, before.ns, before.ns_len);
  return code;
}

/* MALFORMED_AUTH_TOKEN iff params carries an AUTHORIZATION_TOKEN using
 * an alias (moqtrun_disc_auth_refused's twin, this hub's token cache
 * being 0 bytes, SS10.3.1.3) -- the one parameter either namespace
 * kind's update scope admits besides TRACK_NAMESPACE_PREFIX (10.2.2). */
static u64 moqtrun_upd_ns_token_refusal(const moqctl_params* params) {
  return moqtrun_token_uses_alias(moqtrun_auth_token_of(params))
             ? MOQCTL_ERR_MALFORMED_AUTH_TOKEN
             : MOQTRUN_REQ_ACCEPT;
}

static u64 moqtrun_upd_ns_verdict(
    wired_moqt_hub*      hub,
    wired_moqtrun_req*   q,
    const moqctl_params* params,
    const moqctl_param*  pfx) {
  u64 code = moqtrun_upd_ns_token_refusal(params);
  if (code != MOQTRUN_REQ_ACCEPT) return code;
  return pfx ? moqtrun_upd_ns_prefix(hub, q, pfx) : MOQTRUN_REQ_ACCEPT;
}

/* A REQUEST_UPDATE of a PUBLISH_NAMESPACE or SUBSCRIBE_NAMESPACE: the
 * latter may carry TRACK_NAMESPACE_PREFIX; omitted, its prefix is
 * unchanged (10.9.1: "If omitted ... the value for the parameter is
 * unchanged"). A refusal closes the bidi stream (10.9.1), like the
 * namespace's own creation would. */
static void moqtrun_update_ns(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_req*   q,
    const moqctl_params* params) {
  const moqctl_param* pfx =
      moqctl_params_find(params, MOQCTL_PARAM_TRACK_NAMESPACE_PREFIX);
  u64 code = moqtrun_upd_ns_verdict(hub, q, params, pfx);
  if (code != MOQTRUN_REQ_ACCEPT) {
    moqtrun_send_request_error(p, code);
    moqtrun_upd_close_ns(q);
    return;
  }
  moqtrun_queue_request_ok(p, 0);
}

/* 10.15 / 10.18: the receiver MUST verify the request is authorized
 * (moqtrun_subscribe_refused's twin). 1 + *code when refused. */
static int moqtrun_disc_auth_refused(
    const wired_moqt_hub* hub, u64 type, const moqns_req* m, u64* code) {
  const moqctl_token* t = moqtrun_auth_token_of(&m->params);
  *code                 = MOQCTL_ERR_MALFORMED_AUTH_TOKEN;
  if (moqtrun_token_uses_alias(t)) return 1;
  *code = MOQCTL_ERR_UNAUTHORIZED;
  if (!hub->authorize_namespace) return 0;
  return !hub->authorize_namespace(hub->authorize_ns_ctx, type, &m->ns, t);
}

/* Reserved namespaces first (2.4.2/2.4.3; a prefix leading with one is
 * just as reserved), then authorization. */
static int moqtrun_disc_refused(
    const wired_moqt_hub* hub, u64 type, const moqns_req* m, u64* code) {
  *code = MOQCTL_ERR_DOES_NOT_EXIST;
  if (moqtrun_ns_reserved(&m->ns)) return 1;
  return moqtrun_disc_auth_refused(hub, type, m, code);
}

static u64 moqtrun_disc_verdict(
    const wired_moqt_hub* hub,
    wired_moqtrun_req*    q,
    const moqns_req*      m,
    moqtrun_disc_check_fn check) {
  u64 code;
  if (moqtrun_disc_refused(hub, q->kind, m, &code)) return code;
  if (!moqtrun_disc_record(q, &m->ns)) return MOQCTL_ERR_INTERNAL_ERROR;
  return check(hub, q);
}

/* REQUEST_OK makes the request live: the pushes follow it on the stream
 * (moqtrun_disc_sync). A refusal is answered and the stream FINed. */
static void moqtrun_disc_answer(wired_moqtrun_peer* p, u64 err) {
  if (err != MOQTRUN_REQ_ACCEPT) {
    moqtrun_send_request_error(p, err);
    return;
  }
  moqtrun_queue_request_ok(p, 0);
  moqtrun_req_mark_live(p);
}

/* On the control stream there is no request stream to hold the namespace:
 * NOT_SUPPORTED. */
static void moqtrun_handle_disc(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    wired_span            body,
    moqtrun_disc_take_fn  take,
    moqtrun_disc_check_fn check) {
  moqns_req m;
  if (!p->req) {
    moqtrun_send_request_error(p, MOQCTL_ERR_NOT_SUPPORTED);
    return;
  }
  if (take(p->ver, body, &m) != MOQCTL_OK) return;
  moqtrun_disc_answer(p, moqtrun_disc_verdict(hub, p->req, &m, check));
}

static void moqtrun_dispatch_publish_ns(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)peer_idx;
  moqtrun_handle_disc(hub, p, body, moqns_publish_take, moqtrun_disc_pub_check);
}

static void moqtrun_dispatch_subscribe_ns(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)peer_idx;
  moqtrun_handle_disc(
      hub, p, body, moqns_subscribe_take, moqtrun_disc_sub_check);
}

/* NAMESPACE / NAMESPACE_DONE body: the Track Namespace Suffix (10.16-17),
 * its count then the fields after the prefix. */
typedef struct {
  u64        n;
  wired_span fields;
} moqtrun_disc_suffix;

static int moqtrun_encode_disc_suffix(
    wired_mspan buf, usz* off, const void* m) {
  const moqtrun_disc_suffix* s = (const moqtrun_disc_suffix*)m;
  return moqvi_put(buf, off, s->n) && bytes_put(buf, off, s->fields);
}

/* Queues q's whole msg on its stream; 0 when it does not fit yet. */
static int moqtrun_req_push(wired_moqtrun_req* q, wired_span msg) {
  usz before = q->send_lens[q->armed_idx ^ 1];
  moqtrun_req_queue(q, msg);
  return q->send_lens[q->armed_idx ^ 1] != before;
}

/* Queues NAMESPACE or NAMESPACE_DONE (type) for pub's namespace on sub's
 * stream; 1 when queued. */
static int moqtrun_disc_push(
    wired_moqtrun_req* sub, const wired_moqtrun_req* pub, u64 type) {
  u8                  msg[WIRED_MOQTRUN_CTL_HDR_MAX + WIRED_MOQTRUN_MAX_NS];
  u64                 pre_n;
  moqtrun_disc_suffix s;
  wired_span          pre = moqtrun_disc_fields(sub, &pre_n);
  wired_span          all = moqtrun_disc_fields(pub, &s.n);
  s.n -= pre_n;
  s.fields = wired_span_of(all.p + pre.n, all.n - pre.n);
  usz n    = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), type, moqtrun_encode_disc_suffix, &s);
  return moqtrun_req_push(sub, wired_span_of(msg, n));
}

static int moqtrun_disc_wanted(
    const wired_moqtrun_req* sub, const wired_moqtrun_req* pub) {
  return moqtrun_disc_is(pub, MOQNS_T_PUBLISH_NAMESPACE) &&
         moqtrun_disc_under(sub, pub);
}

static u64 moqtrun_disc_bit(usz i) {
  return i < WIRED_MOQTRUN_MAX_REQS ? (u64)1 << i : 0;
}

static int moqtrun_disc_seen(const wired_moqtrun_req* sub, usz i) {
  return (int)((sub->ns_seen >> i) & 1);
}

static int moqtrun_disc_carries(
    const wired_moqt_hub*    hub,
    const wired_moqtrun_req* sub,
    usz                      j,
    const wired_moqtrun_req* q) {
  return moqtrun_disc_seen(sub, j) && moqtrun_disc_same(&hub->reqs[j], q);
}

/* 1 iff sub was already sent a NAMESPACE for q's namespace (through
 * another publisher's slot). */
static int moqtrun_disc_covered(
    const wired_moqt_hub*    hub,
    const wired_moqtrun_req* sub,
    const wired_moqtrun_req* q) {
  for (usz j = 0; j < WIRED_MOQTRUN_MAX_REQS; j++)
    if (moqtrun_disc_carries(hub, sub, j, q)) return 1;
  return 0;
}

static int moqtrun_disc_fresh(
    const wired_moqt_hub*    hub,
    const wired_moqtrun_req* sub,
    const wired_moqtrun_req* q) {
  return moqtrun_disc_wanted(sub, q) && !moqtrun_disc_covered(hub, sub, q);
}

/* A matching namespace sub has not been told of: NAMESPACE. */
static void moqtrun_disc_sync_new(
    wired_moqt_hub* hub, wired_moqtrun_req* sub, usz i) {
  if (!moqtrun_disc_fresh(hub, sub, &hub->reqs[i])) return;
  if (moqtrun_disc_push(sub, &hub->reqs[i], MOQNS_T_NAMESPACE))
    sub->ns_seen |= moqtrun_disc_bit(i);
}

static int moqtrun_disc_heir_at(
    const wired_moqt_hub* hub, usz k, const wired_moqtrun_req* q) {
  return moqtrun_disc_is(&hub->reqs[k], MOQNS_T_PUBLISH_NAMESPACE) &&
         moqtrun_disc_same(&hub->reqs[k], q);
}

/* Index of another live publisher of q's namespace, else
 * WIRED_MOQTRUN_MAX_REQS. */
static usz moqtrun_disc_heir(
    const wired_moqt_hub* hub, const wired_moqtrun_req* q) {
  for (usz k = 0; k < WIRED_MOQTRUN_MAX_REQS; k++)
    if (moqtrun_disc_heir_at(hub, k, q)) return k;
  return WIRED_MOQTRUN_MAX_REQS;
}

/* The withdrawn publisher reqs[i] carried a namespace sub was told of: an
 * heir still publishing it takes it over silently, else NAMESPACE_DONE. */
static void moqtrun_disc_retire(
    wired_moqt_hub* hub, wired_moqtrun_req* sub, usz i) {
  usz k = moqtrun_disc_heir(hub, &hub->reqs[i]);
  if (k == WIRED_MOQTRUN_MAX_REQS &&
      !moqtrun_disc_push(sub, &hub->reqs[i], MOQNS_T_NAMESPACE_DONE))
    return;
  sub->ns_seen &= ~moqtrun_disc_bit(i);
  sub->ns_seen |= moqtrun_disc_bit(k);
}

/* Brings sub's view of reqs[i] in line (10.18): each matching namespace
 * is announced once however many sessions publish it, and NAMESPACE_DONE
 * follows only when the last of them withdraws. A push that does not fit
 * is retried on the next sync. */
static void moqtrun_disc_sync_one(
    wired_moqt_hub* hub, wired_moqtrun_req* sub, usz i) {
  if (!moqtrun_disc_seen(sub, i)) {
    moqtrun_disc_sync_new(hub, sub, i);
    return;
  }
  if (!moqtrun_disc_is(&hub->reqs[i], MOQNS_T_PUBLISH_NAMESPACE))
    moqtrun_disc_retire(hub, sub, i);
}

static void moqtrun_disc_sync_sub(wired_moqt_hub* hub, wired_moqtrun_req* sub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    moqtrun_disc_sync_one(hub, sub, i);
}

/* Every live SUBSCRIBE_NAMESPACE catches up with the published set.
 * ponytail: O(reqs^2) scan per event; index by prefix if the pool grows. */
static void moqtrun_disc_sync(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    if (moqtrun_disc_is(&hub->reqs[i], MOQNS_T_SUBSCRIBE_NAMESPACE))
      moqtrun_disc_sync_sub(hub, &hub->reqs[i]);
}

static int moqtrun_disc_owes(const wired_moqtrun_req* q, usz i) {
  return q->in_use && ((q->ns_seen >> i) & 1);
}

/* 1 iff a live subscription still owes reqs[i] a NAMESPACE_DONE. */
static int moqtrun_disc_held(const wired_moqt_hub* hub, usz i) {
  for (usz k = 0; k < WIRED_MOQTRUN_MAX_REQS; k++)
    if (moqtrun_disc_owes(&hub->reqs[k], i)) return 1;
  return 0;
}

static void moqtrun_handle_not_supported(wired_moqtrun_peer* p) {
  moqtrun_send_request_error(p, MOQCTL_ERR_NOT_SUPPORTED);
}

/* ===== SUBSCRIBE_TRACKS / PUBLISH / PUBLISH_SKIPPED (10.19-10.20) =====
 *
 * The subscriber side of 9.3's "subscribing to namespaces": a
 * SUBSCRIBE_TRACKS request stream carries a Track Namespace Prefix like
 * SUBSCRIBE_NAMESPACE's (moqtrun_disc_* above), but matching tracks get a
 * hub-opened PUBLISH bidi stream addressed to the SUBSCRIBE_TRACKS's own
 * session (or a PUBLISH_SKIPPED on the SUBSCRIBE_TRACKS's own stream)
 * instead of a NAMESPACE push -- 1751/1768. PREFIX_OVERLAP is checked the
 * same way, scoped to kind MOQCTL_T_SUBSCRIBE_TRACKS alone
 * (moqtrun_disc_is), which is 3899's "independent overlap spaces" for
 * free. */

static u64 moqtrun_subtracks_check(
    const wired_moqt_hub* hub, const wired_moqtrun_req* q) {
  int clash =
      moqtrun_disc_any(hub, q, MOQCTL_T_SUBSCRIBE_TRACKS, moqtrun_disc_overlap);
  return clash ? MOQCTL_ERR_PREFIX_OVERLAP : MOQTRUN_REQ_ACCEPT;
}

/* 10.19.1: FORWARD 0 is recorded to reflect as FORWARD 0 on every
 * generated PUBLISH; 1 or omitted stays omitted (T-12, the draft's "or
 * indicate that value by omitting the parameter"). GROUP_ORDER is
 * recorded as given, 0 (absent) staying omitted too. */
static void moqtrun_subtracks_note_params(
    wired_moqtrun_req* q, const moqctl_params* params) {
  const moqctl_param* f = moqctl_params_find(params, MOQCTL_PARAM_FORWARD);
  const moqctl_param* g = moqctl_params_find(params, MOQCTL_PARAM_GROUP_ORDER);
  q->forward_zero       = (u8)(f && f->u8v == 0);
  q->group_order        = g ? (u8)g->u8v : 0;
}

/* Body of moqtrun_dispatch_subscribe_tracks once p->req and the decode are
 * known good, split out to keep the caller's own branch count at the gate. */
static void moqtrun_subtracks_admit(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqns_req* m) {
  u64 code = moqtrun_disc_verdict(hub, p->req, m, moqtrun_subtracks_check);
  if (code == MOQTRUN_REQ_ACCEPT)
    moqtrun_subtracks_note_params(p->req, &m->params);
  moqtrun_disc_answer(p, code);
}

static void moqtrun_dispatch_subscribe_tracks(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  moqns_req m;
  (void)peer_idx;
  if (!p->req) {
    moqtrun_send_request_error(p, MOQCTL_ERR_NOT_SUPPORTED);
    return;
  }
  if (moqns_subscribe_tracks_take(p->ver, body, &m) != MOQCTL_OK) return;
  moqtrun_subtracks_admit(hub, p, &m);
}

/* Flat hub-wide track slot index (wired_moqtrun_req.attempted_tag's own
 * doc): stable across a track's whole life in one peer slot, used only to
 * index that fixed-size array, never stored as a pointer/index into the
 * track itself. */
static usz moqtrun_subtracks_slot(usz peer_idx, usz track_idx) {
  return peer_idx * WIRED_MOQTRUN_MAX_TRACKS_PER_PEER + track_idx;
}

/* 1 iff st (a live SUBSCRIBE_TRACKS) already tried a PUBLISH or
 * PUBLISH_SKIPPED for this track's CURRENT incarnation (design's cache_tag
 * generation guard: a slot reused by a newer PUBLISH is untried again). */
static int moqtrun_subtracks_tried(
    const wired_moqtrun_req* st, const wired_moqtrun_track* t, usz slot) {
  return st->attempted_tag[slot] == t->cache_tag;
}

static void moqtrun_subtracks_mark_tried(
    wired_moqtrun_req* st, const wired_moqtrun_track* t, usz slot) {
  st->attempted_tag[slot] = t->cache_tag;
}

/* 10.19: matches the Track Namespace Prefix (moqtrun_disc_starts, the same
 * byte-prefix-of-fields test SUBSCRIBE_NAMESPACE uses) and excludes tracks
 * published BY the subscriber itself (1753: "excluding tracks published by
 * the subscriber"). */
static int moqtrun_subtracks_matches(
    const wired_moqtrun_req*   st,
    const wired_moqtrun_track* t,
    usz                        pub_idx,
    usz                        st_peer_idx) {
  u64        n_pre, n_all;
  wired_span pre, all;
  if (pub_idx == st_peer_idx) return 0;
  pre = moqtrun_disc_fields(st, &n_pre);
  all = moqtrun_disc_fields_of(wired_span_of(t->ns, t->ns_len), &n_all);
  return moqtrun_disc_starts(pre, all);
}

static int moqtrun_subtracks_candidate(
    const wired_moqtrun_req*   st,
    const wired_moqtrun_track* t,
    usz                        pub_idx,
    usz                        st_peer_idx,
    usz                        slot) {
  if (!t->in_use || moqtrun_subtracks_tried(st, t, slot)) return 0;
  return moqtrun_subtracks_matches(st, t, pub_idx, st_peer_idx);
}

/* T-12: the Parameters this SUBSCRIBE_TRACKS recorded (moqtrun_subtracks_
 * note_params), reflected into one generated PUBLISH. */
static moqctl_params moqtrun_subtracks_publish_params(
    const wired_moqtrun_req* st) {
  moqctl_params out = {0};
  if (st->forward_zero) {
    out.items[out.n].type = MOQCTL_PARAM_FORWARD;
    out.items[out.n].enc  = MOQCTL_PENC_UINT8;
    out.items[out.n].u8v  = 0;
    out.n++;
  }
  if (st->group_order) {
    out.items[out.n].type = MOQCTL_PARAM_GROUP_ORDER;
    out.items[out.n].enc  = MOQCTL_PENC_UINT8;
    out.items[out.n].u8v  = st->group_order;
    out.n++;
  }
  return out;
}

/* Request-stream slot pool, defined in its own section below. */
static wired_moqtrun_req* moqtrun_req_free_slot(wired_moqt_hub* hub);
static wired_moqtrun_req* moqtrun_req_open(
    wired_moqtrun_req* q, wired_wt_session* s, u64 stream_id);

/* Claims a free hub-wide request slot for a hub-opened PUBLISH, addressed
 * to st_peer's session (the SUBSCRIBE_TRACKS's own receiver per 10.9/1751)
 * and owned by st's request_id (moqtrun.h's pub_origin_rid doc). Never the
 * per-session WIRED_MOQTRUN_MAX_REQS_PER_SESSION cap, which bounds
 * CLIENT-opened request streams only. */
static wired_moqtrun_req* moqtrun_subtracks_claim_slot(
    wired_moqt_hub* hub, wired_moqtrun_peer* st_peer, u64 st_rid) {
  wired_moqtrun_req* q = moqtrun_req_free_slot(hub);
  if (!q) return 0;
  moqtrun_req_open(q, st_peer->wt, 0);
  q->pub_origin_rid = st_rid;
  q->request_id     = st_peer->request_id_next;
  st_peer->request_id_next += 2;
  return q;
}

static int moqtrun_subtracks_encode_pub(
    wired_mspan buf, usz* off, const void* m) {
  return moqctl_publish_encode(buf, off, m);
}

/* Opens a fresh PUBLISH bidi stream on st_peer's session for t, naming q's
 * request_id and st_peer's session alias for t (10.9; draft-22 3.1.3,
 * moqtrun_session_alias), kept on q as pub_alias; 1 sent, 0 when the transport
 * has no bidi stream (or equivalent resource) to open -- the caller falls back
 * to PUBLISH_SKIPPED (1767-1771: "no available bidirectional streams or
 * any other reason"). */
static int moqtrun_subtracks_open_pub(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        st_peer,
    wired_moqtrun_req*         q,
    const wired_moqtrun_track* t,
    const wired_moqtrun_req*   st) {
  u8
                 msg[WIRED_MOQTRUN_CTL_HDR_MAX + WIRED_MOQTRUN_MAX_NS +
                     WIRED_MOQTRUN_MAX_NAME + 32];
  moqctl_publish m   = {0};
  usz            off = 0;
  i64            sid;
  usz            n;
  m.request_id  = q->request_id;
  m.track_alias = moqtrun_session_alias(hub, (usz)(st_peer - hub->peers), t);
  m.params      = moqtrun_subtracks_publish_params(st);
  moqctl_ns_take(wired_span_of(t->ns, t->ns_len), &off, &m.name.ns);
  m.name.name = wired_span_of(t->name, t->name_len);
  n           = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_PUBLISH,
      moqtrun_subtracks_encode_pub, &m);
  sid = hub->io.open_bidi_stream(st_peer->wt, wired_span_of(msg, n));
  if (sid < 0) return 0;
  q->stream_id     = (u64)sid;
  q->opened        = 1;
  q->kind          = MOQCTL_T_PUBLISH;
  q->pub_track_tag = t->cache_tag;
  q->pub_alias     = m.track_alias;
  return 1;
}

/* 10.20: Track Namespace Suffix (past st's own Prefix, like
 * moqtrun_disc_push's NAMESPACE) then Track Name, queued on st's own
 * stream -- no new stream, per the draft's own wording ("sends ... on the
 * SUBSCRIBE_TRACKS response stream"). */
static int moqtrun_subtracks_encode_skip(
    wired_mspan buf, usz* off, const void* m) {
  return moqns_pub_skipped_encode(buf, off, m);
}

/* t's namespace fields past st's own Prefix (10.20's "Track Namespace
 * Suffix"), decoded straight into a moqctl_ns by re-counting the
 * remainder -- the suffix byte layout (Length-prefixed fields, no count
 * of its own here) is identical to a bare Track Namespace's own fields,
 * so moqctl_ns_take's Length-prefixed-field reader applies unchanged once
 * fed just the suffix's field count. */
static void moqtrun_subtracks_ns_suffix(
    const wired_moqtrun_req* st, const wired_moqtrun_track* t, moqctl_ns* out) {
  u8         buf[WIRED_MOQTRUN_MAX_NS + 9];
  u64        pre_n, all_n;
  usz        put = 0, take = 0;
  wired_span pre = moqtrun_disc_fields(st, &pre_n);
  wired_span all =
      moqtrun_disc_fields_of(wired_span_of(t->ns, t->ns_len), &all_n);
  wired_span suf = wired_span_of(all.p + pre.n, all.n - pre.n);
  moqvi_put(wired_mspan_of(buf, sizeof buf), &put, all_n - pre_n);
  bytes_memcpy(buf + put, suf.p, suf.n);
  moqctl_ns_take(wired_span_of(buf, put + suf.n), &take, out);
}

static void moqtrun_subtracks_send_skipped(
    wired_moqtrun_req* st, const wired_moqtrun_track* t) {
  moqns_pub_skipped m;
  u8
      msg[WIRED_MOQTRUN_CTL_HDR_MAX + WIRED_MOQTRUN_MAX_NS +
          WIRED_MOQTRUN_MAX_NAME];
  usz n;
  moqtrun_subtracks_ns_suffix(st, t, &m.ns);
  m.name = wired_span_of(t->name, t->name_len);
  n      = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_PUBLISH_SKIPPED,
      moqtrun_subtracks_encode_skip, &m);
  moqtrun_req_queue(st, wired_span_of(msg, n));
}

/* 1 iff q is non-0 and names a successfully opened PUBLISH. */
static int moqtrun_subtracks_opened(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        st_peer,
    wired_moqtrun_req*         q,
    const wired_moqtrun_track* t,
    const wired_moqtrun_req*   st) {
  if (!q) return 0;
  return moqtrun_subtracks_open_pub(hub, st_peer, q, t, st);
}

/* 1 iff q names a successfully opened PUBLISH; releases a claimed-but-
 * unopened slot before reporting failure, so the caller's only remaining
 * branch is "sent or not". */
static int moqtrun_subtracks_try_open(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        st_peer,
    wired_moqtrun_req*         q,
    const wired_moqtrun_track* t,
    const wired_moqtrun_req*   st) {
  if (moqtrun_subtracks_opened(hub, st_peer, q, t, st)) return 1;
  if (q) q->in_use = 0;
  return 0;
}

/* One candidate (st, t) pair: PUBLISH if a bidi stream opens, else
 * PUBLISH_SKIPPED (the resource-exhaustion choice settled in design.md
 * section 5) -- and mark the attempt either way (exactly once). */
static void moqtrun_subtracks_attempt(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  st_peer,
    wired_moqtrun_req*   st,
    wired_moqtrun_track* t,
    usz                  slot) {
  wired_moqtrun_req* q =
      moqtrun_subtracks_claim_slot(hub, st_peer, st->request_id);
  if (!moqtrun_subtracks_try_open(hub, st_peer, q, t, st))
    moqtrun_subtracks_send_skipped(st, t);
  moqtrun_subtracks_mark_tried(st, t, slot);
}

/* One (SUBSCRIBE_TRACKS, track) pair at hub->reqs[i]: attempts it when it
 * is both a live SUBSCRIBE_TRACKS and a fresh candidate, else a no-op --
 * split out so the scanning loop above carries no branches of its own. */
static void moqtrun_subtracks_sync_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_req*   st,
    wired_moqtrun_track* t,
    usz                  pub_idx,
    usz                  slot) {
  wired_moqtrun_peer* sp;
  usz                 st_idx;
  if (!moqtrun_disc_is(st, MOQCTL_T_SUBSCRIBE_TRACKS)) return;
  sp     = moqtrun_find_by_wt(hub, st->wt);
  st_idx = (usz)(sp - hub->peers);
  if (moqtrun_subtracks_candidate(st, t, pub_idx, st_idx, slot))
    moqtrun_subtracks_attempt(hub, sp, st, t, slot);
}

/* Every live SUBSCRIBE_TRACKS against every in-use track of peer pub_idx:
 * a hub-wide O(sessions*tracks*reqs) scan, the same shape as
 * moqtrun_disc_sync's (ponytail: fine at this hub's fixed small
 * capacities). */
static void moqtrun_subtracks_sync_track(
    wired_moqt_hub* hub, usz pub_idx, usz track_idx) {
  wired_moqtrun_track* t    = &hub->peers[pub_idx].tracks[track_idx];
  usz                  slot = moqtrun_subtracks_slot(pub_idx, track_idx);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    moqtrun_subtracks_sync_one(hub, &hub->reqs[i], t, pub_idx, slot);
}

static void moqtrun_subtracks_sync_peer(wired_moqt_hub* hub, usz pub_idx) {
  for (usz ti = 0; ti < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; ti++)
    moqtrun_subtracks_sync_track(hub, pub_idx, ti);
}

static void moqtrun_subtracks_sync(wired_moqt_hub* hub) {
  for (usz pi = 0; pi < WIRED_MOQTRUN_MAX_SESSIONS; pi++)
    if (hub->peers[pi].in_use) moqtrun_subtracks_sync_peer(hub, pi);
}

/* A track's retirement (unpublish / slot reuse, T-07/T-08): every PUBLISH
 * stream this hub opened for it is reset, dangling-free, the same
 * fill-design pattern moqtrun_fills_upstream_gone uses for fetch fills.
 * Already-answered (q->live, REQUEST_OK) slots are reset too -- the
 * SUBSCRIBE_TRACKS-established subscription cannot outlive the track that
 * no longer exists, unlike a SUBSCRIBE_TRACKS cancel (T-10), which leaves
 * them alone. */
static int moqtrun_subtracks_pub_of_tag(const wired_moqtrun_req* q, u64 tag) {
  return q->in_use && q->pub_origin_rid && q->pub_track_tag == tag;
}

static void moqtrun_subtracks_pub_reset(
    wired_moqt_hub* hub, wired_moqtrun_req* q) {
  if (q->opened)
    hub->io.stream_reset(q->wt, q->stream_id, MOQTRUN_RESET_INTERNAL_ERROR);
  q->in_use = 0;
}

static void moqtrun_subtracks_track_gone(wired_moqt_hub* hub, u64 tag) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    if (moqtrun_subtracks_pub_of_tag(&hub->reqs[i], tag))
      moqtrun_subtracks_pub_reset(hub, &hub->reqs[i]);
}

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

static void moqtrun_dispatch_fetch(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  moqtrun_handle_fetch(hub, p, peer_idx, body);
}

static void moqtrun_dispatch_not_supported(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)hub;
  (void)peer_idx;
  (void)body;
  moqtrun_handle_not_supported(p);
}

typedef int (*moqtrun_goaway_take_fn)(wired_span, usz*, moqctl_goaway*);

/* draft-18 SS10.4: a control-stream GOAWAY ends with a Request ID. */
static moqtrun_goaway_take_fn moqtrun_goaway_decoder(int ver) {
  return (moqver_caps(ver) & MOQVER_CAP_GOAWAY_REQID) ? moqctl_goaway18_take
                                                      : moqctl_goaway_take;
}

/* draft-ietf-moq-transport-19 10.4: a GOAWAY on the control stream must
 * be well formed in p's draft, carry no New Session URI (the hub is the
 * server), and be the session's first. */
static int moqtrun_goaway_bad(
    wired_moqtrun_peer* p, wired_span body, moqctl_goaway* g) {
  usz off = 0;
  if (moqtrun_goaway_decoder(p->ver)(body, &off, g) != MOQCTL_OK ||
      g->new_session_uri.n)
    return 1;
  return moqsess_step(&p->sess, MOQSESS_EV_RECV_GOAWAY) != MOQSESS_CLOSE_NONE;
}

/* draft-18 SS10.4: the Request ID names one of the hub's own Request IDs,
 * which are odd (server); the wrong parity is INVALID_REQUEST_ID. */
static int moqtrun_goaway_rid_bad(
    const wired_moqtrun_peer* p, const moqctl_goaway* g) {
  return (moqver_caps(p->ver) & MOQVER_CAP_GOAWAY_REQID) &&
         !(g->request_id & 1);
}

/* Session close code a control-stream GOAWAY calls for; 0 for none. */
static u32 moqtrun_goaway_close(wired_moqtrun_peer* p, wired_span body) {
  moqctl_goaway g = {0};
  if (moqtrun_goaway_bad(p, body, &g))
    return WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION;
  return moqtrun_goaway_rid_bad(p, &g) ? WIRED_MOQTRUN_CLOSE_INVALID_REQUEST_ID
                                       : 0;
}

/* A GOAWAY on a request stream asks to migrate that one request; the
 * route already refuses a second one, and the hub opens no requests to
 * move. One on the control stream is recorded, a bad one closes the
 * session with PROTOCOL_VIOLATION. */
static void moqtrun_dispatch_goaway(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)peer_idx;
  if (p->req) return;
  u32 code = moqtrun_goaway_close(p, body);
  if (code) moqtrun_close_with(hub, p, code);
}

/* draft-19 3.3: one control stream per peer -- a 2nd one (or a 2nd
 * SETUP) closes the session with PROTOCOL_VIOLATION. */
static void moqtrun_second_ctl(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  moqsess_step(&p->sess, MOQSESS_EV_SECOND_CTRL);
  moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
}

/* A SETUP after one was already accepted, or on a stream other than the
 * accepted client control stream. */
static int moqtrun_setup_second(const wired_moqtrun_peer* p) {
  return p->setup_recv ||
         (p->peer_ctl_set && p->peer_ctl_stream_id != p->rx_sid);
}

/* draft-19 10.4: PATH and AUTHORITY MUST NOT be used over WebTransport;
 * each names its own 3.5 close code. */
static u32 moqtrun_setup_opt_bad(const moqctl_setup* m) {
  if (m->has_path) return WIRED_MOQTRUN_CLOSE_INVALID_PATH;
  return m->has_authority ? WIRED_MOQTRUN_CLOSE_INVALID_AUTHORITY : 0;
}

/* Close code a client SETUP body calls for; 0 = accept (*m decoded). */
static u32 moqtrun_setup_take_code(wired_span body, moqctl_setup* m) {
  usz off = 0;
  if (moqctl_setup_take(body, &off, m) != MOQCTL_OK)
    return WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION;
  return moqtrun_setup_opt_bad(m);
}

static void moqtrun_impl_copy(wired_moqtrun_peer* p, const moqctl_setup* m) {
  usz n = (usz)u64_min(m->implementation.n, WIRED_MOQTRUN_IMPL_MAX);
  if (!m->has_implementation) return;
  bytes_memcpy(p->peer_impl, m->implementation.p, n);
  p->peer_impl_len = n;
  p->peer_has_impl = 1;
}

/* Records the accepted client SETUP: the stream it rode becomes the
 * client control stream, its MOQT_IMPLEMENTATION is copied, and the
 * session machine advances (3.3: Established once both sides' SETUP are
 * done). */
static void moqtrun_setup_accept(wired_moqtrun_peer* p, const moqctl_setup* m) {
  p->peer_ctl_set       = 1;
  p->peer_ctl_stream_id = p->rx_sid;
  p->setup_recv         = 1;
  moqtrun_impl_copy(p, m);
  moqsess_step(&p->sess, MOQSESS_EV_RECV_SETUP);
}

/* draft-19 3.3/10.4: the client's SETUP, on whichever stream 3.3's
 * leniency lets it arrive. Never reached via a request stream --
 * moqtrun_req_allowed rejects SETUP there first. */
static void moqtrun_dispatch_setup(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  moqctl_setup m;
  u32          code;
  (void)peer_idx;
  if (moqtrun_setup_second(p)) {
    moqtrun_second_ctl(hub, p);
    return;
  }
  code = moqtrun_setup_take_code(body, &m);
  if (code) {
    moqtrun_close_with(hub, p, code);
    return;
  }
  moqtrun_setup_accept(p, &m);
}

/* draft-22 9.10: PUBLISH_STATE_NOTIFY rides a subscription's request
 * stream and only from its publisher -- the follow-on gate
 * (moqtrun_req_pub_follow) already admits it there, unanswered. Anywhere
 * else (the control stream lands here with no request; a subscriber's or
 * another request's stream never reaches this handler) the session
 * closes with PROTOCOL_VIOLATION. */
static void moqtrun_dispatch_pub_notify(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)peer_idx;
  (void)body;
  if (p->req) return;
  moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
}

/* A message with no request to refuse: consumed by its Length, no reply. */
static void moqtrun_dispatch_skip(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)hub;
  (void)p;
  (void)peer_idx;
  (void)body;
}

/* PUBLISH_DONE relay (its own section below, draft 10.11). */
static void moqtrun_dispatch_pub_done(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
static void moqtrun_pubdone_sweep(wired_moqt_hub* hub);
static void moqtrun_pubdone_flush(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 rid);

/* First-type table (draft table in ctl.h's peek_type doc): only PUBLISH,
 * SUBSCRIBE, FETCH, TRACK_STATUS, PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE and
 * SUBSCRIBE_TRACKS (and REQUEST_UPDATE of a SUBSCRIBE) are implemented;
 * every other First type this hub can see on a fresh request stream gets
 * NOT_SUPPORTED. GOAWAY is not a First type but may legally appear
 * mid-stream, so it is routed the same table for request-stream dispatch
 * below. */
static const struct {
  u64            type;
  moqtrun_ctl_fn fn;
} moqtrun_ctl_table[] = {
    {MOQCTL_T_SETUP, moqtrun_dispatch_setup},
    {MOQCTL_T_PUBLISH, moqtrun_dispatch_publish},
    {MOQCTL_T_SUBSCRIBE, moqtrun_dispatch_subscribe},
    {MOQFETCH_T_FETCH, moqtrun_dispatch_fetch},
    {MOQNS_T_PUBLISH_NAMESPACE, moqtrun_dispatch_publish_ns},
    {MOQNS_T_SUBSCRIBE_NAMESPACE, moqtrun_dispatch_subscribe_ns},
    {MOQCTL_T_SUBSCRIBE_TRACKS, moqtrun_dispatch_subscribe_tracks},
    {MOQTSTAT_T_TRACK_STATUS, moqtrun_handle_tstat},
    {MOQTSTAT_T_REQUEST_UPDATE, moqtrun_handle_update},
    {MOQCTL_T_GOAWAY, moqtrun_dispatch_goaway},
    {MOQCTL_T_PUBLISH_STATE_NOTIFY, moqtrun_dispatch_pub_notify},
    /* draft SS10 known non-request messages this hub does not implement:
     * nothing carries a Request ID to answer, so they are skipped. */
    {MOQNS_T_NAMESPACE, moqtrun_dispatch_skip},
    {MOQNS_T_NAMESPACE_DONE, moqtrun_dispatch_skip},
    {MOQCTL_T_PUBLISH_SKIPPED, moqtrun_dispatch_skip},
    {MOQFETCH_T_FETCH_OK, moqtrun_dispatch_skip},
    {MOQCTL_T_PUBLISH_DONE, moqtrun_dispatch_pub_done},
};
#define MOQTRUN_CTL_TABLE_N \
  (sizeof(moqtrun_ctl_table) / sizeof(moqtrun_ctl_table[0]))

static moqtrun_ctl_fn moqtrun_ctl_lookup(u64 type) {
  for (usz i = 0; i < MOQTRUN_CTL_TABLE_N; i++)
    if (moqtrun_ctl_table[i].type == type) return moqtrun_ctl_table[i].fn;
  return moqtrun_dispatch_not_supported;
}

/* Closes p's session with code, after which nothing more is sent on it;
 * 0 when the io table has no close_session. */
static int moqtrun_peer_close(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u32 code) {
  if (!hub->io.close_session) return 0;
  hub->io.close_session(p->wt, code, wired_span_of(0, 0));
  p->closing = 1;
  return 1;
}

/* Closes p's session with code. Every later byte of the stream being
 * handled is discarded (its skip never runs out). An io table without
 * close_session skips the message by its Length instead and keeps the
 * stream alive. */
static void moqtrun_close_with(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u32 code) {
  wired_moqtrun_ctl_asm* a = moqtrun_cur_asm(p);
  if (!moqtrun_peer_close(hub, p, code)) return;
  a->at   = a->n;
  a->skip = (usz)-1;
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

/* ===================== request streams ===================== */

/* draft-ietf-moq-transport-19 3.3: the seven types a request stream may
 * begin with. */
static const u64 moqtrun_req_first[] = {
    MOQCTL_T_SUBSCRIBE,        MOQCTL_T_PUBLISH,
    MOQFETCH_T_FETCH,          MOQTSTAT_T_TRACK_STATUS,
    MOQNS_T_PUBLISH_NAMESPACE, MOQNS_T_SUBSCRIBE_NAMESPACE,
    MOQCTL_T_SUBSCRIBE_TRACKS,
};
#define MOQTRUN_REQ_FIRST_N \
  (sizeof(moqtrun_req_first) / sizeof(moqtrun_req_first[0]))

static int moqtrun_req_is_first(u64 type) {
  for (usz i = 0; i < MOQTRUN_REQ_FIRST_N; i++)
    if (moqtrun_req_first[i] == type) return 1;
  return 0;
}

/* draft 10.9: REQUEST_UPDATE follows any request but TRACK_STATUS. */
static int moqtrun_req_update_ok(u64 kind, u64 type) {
  return type == MOQTSTAT_T_REQUEST_UPDATE && kind != MOQTSTAT_T_TRACK_STATUS;
}

/* draft 10.11/10.20 and draft-22 9.10: messages only a PUBLISH's sender
 * may follow its request with on its own stream. PUBLISH_STATE_NOTIFY
 * reaches here on a draft-22 session alone -- the other drafts' peek
 * already closed on it as an unknown type. */
static int moqtrun_req_pub_follow(u64 type) {
  return type == MOQCTL_T_PUBLISH_DONE || type == MOQCTL_T_PUBLISH_SKIPPED ||
         type == MOQCTL_T_PUBLISH_STATE_NOTIFY;
}

static int moqtrun_req_done_ok(u64 kind, u64 type) {
  return kind == MOQCTL_T_PUBLISH && moqtrun_req_pub_follow(type);
}

/* draft 10.4: GOAWAY may appear on a request stream, but only once. */
static int moqtrun_req_goaway_ok(const wired_moqtrun_req* q, u64 type) {
  return type == MOQCTL_T_GOAWAY && !q->goaway;
}

/* What the requester may send after its request. */
static int moqtrun_req_follow_ok(const wired_moqtrun_req* q, u64 type) {
  return moqtrun_req_goaway_ok(q, type) ||
         moqtrun_req_update_ok(q->kind, type) ||
         moqtrun_req_done_ok(q->kind, type);
}

/* kind 0: nothing read yet, so type must open the stream. */
static int moqtrun_req_allowed(const wired_moqtrun_req* q, u64 type) {
  if (!q->kind) return moqtrun_req_is_first(type);
  return moqtrun_req_follow_ok(q, type);
}

/* Records the request q carries: its type and Request ID (the first field
 * of every request message, draft 10.1), and whether GOAWAY was seen. */
static void moqtrun_req_note(wired_moqtrun_req* q, u64 type, wired_span body) {
  usz off = 0;
  q->goaway |= type == MOQCTL_T_GOAWAY;
  if (q->kind) return;
  q->kind = type;
  moqvi_take(body, &off, &q->request_id);
}

/* A request-stream message out of place (draft 3.3: a bidi stream begins
 * with a request; draft 10: a "First" type only first, and every later
 * message must belong to that request) closes the session with
 * PROTOCOL_VIOLATION; the rest goes to the shared handlers. */
static moqtrun_ctl_fn moqtrun_req_route(
    wired_moqtrun_req* q, u64 type, wired_span body) {
  if (!moqtrun_req_allowed(q, type)) return moqtrun_dispatch_close;
  moqtrun_req_note(q, type, body);
  return moqtrun_ctl_lookup(type);
}

static int moqtrun_peek_known(int peek) {
  return peek == MOQCTL_OK || peek == MOQCTL_KNOWN_UNIMPLEMENTED;
}

/* draft-ietf-moq-transport-19 10.4: after the hub sent GOAWAY on this
 * session, a new request is refused GOING_AWAY. */
static void moqtrun_dispatch_going_away(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)hub;
  (void)peer_idx;
  (void)body;
  moqtrun_send_request_error(p, MOQCTL_ERR_GOING_AWAY);
}

static int moqtrun_is_late(const wired_moqtrun_peer* p, u64 type) {
  return p->sess.goaway_sent && moqtrun_req_is_first(type);
}

/* fn, unless the message is a request arriving late (a closing route
 * still wins). */
static moqtrun_ctl_fn moqtrun_late_route(
    const wired_moqtrun_peer* p, u64 type, moqtrun_ctl_fn fn) {
  if (fn != moqtrun_dispatch_close && moqtrun_is_late(p, type))
    return moqtrun_dispatch_going_away;
  return fn;
}

/* A request message (a First type or REQUEST_UPDATE, draft 10.1) starts
 * with the Request ID it consumes. */
static int moqtrun_rid_counts(int peek, u64 type) {
  return moqtrun_peek_known(peek) &&
         (moqtrun_req_is_first(type) || type == MOQTSTAT_T_REQUEST_UPDATE);
}

/* Keeps p->peer_rid_next past every Request ID p has sent (draft-18
 * SS10.4 GOAWAY Request ID). */
static void moqtrun_rid_note(
    wired_moqtrun_peer* p, int peek, u64 type, wired_span body) {
  usz off  = 0;
  u64 rid  = 0;
  u64 next = ~(u64)0; /* rid + 2 saturates: u64_add_ok keeps it on overflow */
  if (!moqtrun_rid_counts(peek, type)) return;
  if (!moqvi_take(body, &off, &rid)) return; /* no ID read: nothing moves */
  u64_add_ok(rid, 2, &next);
  p->peer_rid_next = u64_max(p->peer_rid_next, next);
}

static moqtrun_ctl_fn moqtrun_msg_route(
    wired_moqtrun_peer* p, int peek, u64 type, wired_span body) {
  peek = moqctl_type_ver(p->ver, peek, &type);
  moqtrun_rid_note(p, peek, type, body);
  if (p->req && moqtrun_peek_known(peek))
    return moqtrun_late_route(p, type, moqtrun_req_route(p->req, type, body));
  return moqtrun_late_route(p, type, moqtrun_ctl_route(peek, type));
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
  bytes_move_down(a->buf, a->buf + a->at, keep);
  usz take = (usz)u64_min(sizeof a->buf - keep, data->n);
  bytes_memcpy(a->buf + keep, data->p, take);
  a->n  = keep + take;
  a->at = 0;
  moqtrun_span_drop(data, take);
}

/* a's unread bytes. */
static wired_span moqtrun_asm_rest(const wired_moqtrun_ctl_asm* a) {
  return wired_span_of(a->buf + a->at, a->n - a->at);
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
  wired_span rest  = moqtrun_asm_rest(a);
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

/* Routes every complete message the handled stream's reassembly holds. */
static void moqtrun_ctl_drain(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx) {
  u64        type = 0;
  wired_span body = {0, 0};
  int        r;
  while ((r = moqtrun_asm_pop(moqtrun_cur_asm(p), &type, &body)) !=
         MOQCTL_INSUFFICIENT)
    moqtrun_msg_route(p, r, type, body)(hub, p, peer_idx, body);
}

/* Dispatches every complete control message found in data on the stream
 * p is handling (p->req, else the control stream), prefixed by the
 * incomplete tail the previous call left in that stream's reassembly -- a
 * message may arrive split across calls. peer_idx is
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
  moqtrun_flush_cur(&hub->io, p);
  do {
    moqtrun_asm_push(moqtrun_cur_asm(p), &data);
    moqtrun_ctl_drain(hub, p, peer_idx);
  } while (data.n > 0);
  moqtrun_flush_cur(&hub->io, p);
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
  h.type             = MOQDATA_MSG_TYPE;
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

/* 1 iff Group g may open for sub slot i: its peer is connected, g passes
 * the Location Filter (5.1.4), and g's Object -- produced when g began --
 * is not past the OBJECT_DELIVERY_TIMEOUT (draft 8: no stream is opened
 * for it). */
static int moqtrun_live_due(
    const wired_moqt_hub* hub, const wired_moqtrun_peer* dst, usz i, u64 g) {
  const wired_moqtrun_live* live = &hub->live;
  const wired_moqtrun_sub*  s    = &live->track.subs[i];
  u64                       born = live->t0_ms + g * live->group_ms;
  return dst->in_use && moqtrun_sub_wants_group(s, g) &&
         !moqtrun_sub_late(s, live->last_now_ms - born);
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
  if (!moqtrun_live_due(hub, dst, i, g)) return;
  if (hub->io.send_uni2(dst->wt, wired_span_of(head, hn), frag) < 0) return;
  live->track.subs[i].stream_count++;
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

static void moqtrun_reqs_tick(wired_moqt_hub* hub);

static void moqtrun_drain_tick(wired_moqt_hub* hub, u64 now_ms);

/* The hub's own live track: the Group current at now_ms to every
 * subscriber behind it. */
static void moqtrun_live_tick(wired_moqt_hub* hub, u64 now_ms) {
  if (!hub->live.track.in_use) return;
  u64 g = moqtrun_live_group_at(&hub->live, now_ms);
  moqtrun_track_note(&hub->live.track, g, 0);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    moqtrun_live_serve_sub(hub, i, g);
}

void wired_moqt_tick(wired_moqt_hub* hub, u64 now_ms) {
  hub->live.last_now_ms = now_ms;
  moqtrun_fetches_tick(hub, 0); /* ascending backlog before live rounds */
  moqtrun_rel_tick_all(hub, now_ms);
  moqtrun_drain_tick(hub, now_ms);
  moqtrun_pubdone_sweep(hub);
  moqtrun_reqs_tick(hub);
  moqtrun_live_tick(hub, now_ms);
  moqtrun_fetches_tick(hub, 1); /* a descending fill waits for them */
}

/* Records slot for peer_idx, replies SUBSCRIBE_OK with the live track's
 * own alias, and sends the Group current at the last tick at once (its
 * fragment starts with a keyframe). The subscription's Location Filter
 * start still gates that send (moqtrun_live_due, 5.1.4): a start behind
 * the live edge is effectively clamped to the current Group, a future
 * start keeps the attach silent until the clock reaches it. */
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

/* SUBSCRIBE for the live track: a held subscription is re-answered
 * (moqtrun_sub_held_reply, nothing re-sent), anyone else is attached
 * and served the current Group. */
static void moqtrun_subscribe_live(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m) {
  wired_moqtrun_track* t    = &hub->live.track;
  wired_moqtrun_sub*   held = moqtrun_track_sub_of_peer(t, peer_idx);
  if (moqtrun_sub_held_reply(p, t, held)) return;
  wired_moqtrun_sub* slot = moqtrun_sub_slot(t);
  if (!slot) {
    moqtrun_send_request_error(p, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  moqtrun_live_attach(hub, p, slot, peer_idx, m);
}

/* ===================== data-stream (Object) relay ===================== */

/* draft-ietf-moq-transport-19 10.2.7: SUBSCRIBER_PRIORITY defaults to
 * 128. */
static u8 moqtrun_sub_prio(const wired_moqtrun_sub* s) {
  return s->has_priority ? s->priority : 128;
}

/* The Publisher Priority of the SUBGROUP_HEADER head starts with: 128
 * (6306: the default) when the DEFAULT_PRIORITY bit omits it, or head does
 * not decode.
 * ponytail: the DEFAULT_PUBLISHER_PRIORITY Track Property (12.4) is not
 * parsed, so an omitted priority is always 128; read it from PUBLISH when
 * a publisher sets one. */
static u8 moqtrun_pub_prio(wired_span head) {
  usz            off = 0;
  moqdata_subhdr h;
  if (moqdata_subhdr_take(head, &off, &h) != MOQDATA_OK) return 128;
  return moqdata_type_default_priority(h.type) ? 128 : (u8)h.priority;
}

/* Sets the urgency (WIRED_MOQTRUN_URGENCY) of subscriber stream sid just
 * opened for sub, head being its opening bytes. */
static void moqtrun_prio_set(
    wired_moqt_hub*          hub,
    wired_wt_session*        wt,
    i64                      sid,
    const wired_moqtrun_sub* sub,
    wired_span               head) {
  if (!hub->io.stream_priority || sid < 0) return;
  hub->io.stream_priority(
      wt, (u64)sid,
      WIRED_MOQTRUN_URGENCY(moqtrun_sub_prio(sub), moqtrun_pub_prio(head)));
}

/* One-shot relay of wire to one subscriber: a fresh uni stream, sent and
 * FIN'd in a single io.send_uni call -- the whole-message-in-one-call path
 * (a publisher stream whose data AND fin arrived together). */
static void moqtrun_relay_to_one(
    wired_moqt_hub* hub, wired_moqtrun_sub* sub, wired_span wire) {
  wired_moqtrun_peer* dst = &hub->peers[sub->session_idx];
  if (!dst->in_use) return;
  /* A refused one-shot open loses this subscriber's whole message (chat's
   * 1 stream = 1 message); count it like the keep-open path's open
   * failures -- stat_open_drop's own doc always promised this loss is
   * never silent, but this call site used to discard the return. */
  i64 sid = hub->io.send_uni(dst->wt, wire);
  hub->stat_open_drop += sid < 0;
  sub->stream_count += sid >= 0;
  moqtrun_prio_set(hub, dst->wt, sid, sub, wire);
}

static void moqtrun_subgroup_scan(
    wired_span wire, wired_moqtrun_track* t, moqdata_objseq* seq, u64* group);

/* wire cut to sub's End Object (moqtrun_wire_cutoff), re-reading wire's own
 * SUBGROUP_HEADER for the Object decode's starting point and seq -- wire
 * always starts with one here (moqtrun_relay_object's caller only reaches
 * this for a fresh stream). A header that fails to decode is passed whole;
 * moqtrun_subgroup_scan already did (and acted on) the real decode. */
static wired_span moqtrun_hdr_cutoff(
    const wired_moqtrun_sub* s, wired_span wire, u64 group) {
  usz            off = 0;
  moqdata_subhdr hdr;
  if (moqdata_subhdr_take(wire, &off, &hdr) != MOQDATA_OK) return wire;
  moqdata_objseq seq = moqdata_objseq_of(hdr.type);
  usz            cut = moqtrun_wire_cutoff(s, wire, off, seq, group);
  return wired_span_of(wire.p, cut);
}

/* Offsets of wire's Track Alias -- the vi64 right after the Type in a
 * SUBGROUP_HEADER (draft-22 11.3.1) and an OBJECT_DATAGRAM (11.2.1)
 * alike -- and its value; 0 when either does not decode. */
static int moqtrun_alias_spot(wired_span wire, usz* at, usz* end, u64* cur) {
  usz off = 0;
  u64 type;
  if (!moqvi_take(wire, &off, &type)) return 0;
  *at = off;
  if (!moqvi_take(wire, &off, cur)) return 0;
  *end = off;
  return 1;
}

/* 1 iff wire names another alias than a and a re-spelled copy fits
 * hub->alias_scratch. */
static int moqtrun_alias_respell(
    const wired_moqt_hub* hub, wired_span wire, u64 a, usz* at, usz* end) {
  u64 cur = a;
  return moqtrun_alias_spot(wire, at, end, &cur) && cur != a &&
         wire.n + 8 <= sizeof hub->alias_scratch;
}

/* wire as its destination must see it: carrying a, the alias that
 * session's SUBSCRIBE_OK named (draft-22 3.1.3). wire itself when it
 * already does (the common case: moqtrun_session_alias prefers the
 * publisher's own), else a copy staged in hub->alias_scratch, valid
 * until the next call. Only a stream head or a datagram is passed here
 * -- never a header-less continuation round. */
static wired_span moqtrun_alias_splice(
    wired_moqt_hub* hub, wired_span wire, u64 a) {
  usz at = 0, end = 0;
  if (!moqtrun_alias_respell(hub, wire, a, &at, &end)) return wire;
  bytes_memcpy(hub->alias_scratch, wire.p, at);
  usz n = at + moqvi_encode(hub->alias_scratch + at, a);
  bytes_memcpy(hub->alias_scratch + n, wire.p + end, wire.n - end);
  return wired_span_of(hub->alias_scratch, n + wire.n - end);
}

static void moqtrun_relay_object(
    wired_moqt_hub* hub, wired_moqtrun_track* track, wired_span wire) {
  moqdata_objseq seq;
  u64            group = 0;
  moqtrun_subgroup_scan(wire, 0, &seq, &group);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (moqtrun_sub_gets(&track->subs[i], group))
      moqtrun_relay_to_one(
          hub, &track->subs[i],
          moqtrun_alias_splice(
              hub, moqtrun_hdr_cutoff(&track->subs[i], wire, group),
              track->subs[i].track_alias));
}

/* --- relay map: one entry per in-flight publisher stream (moqtrun.h's
 * wired_moqtrun_relay doc -- keyed by the PUBLISHER's stream id so several
 * of one track's streams can be forwarded concurrently). --- */

static usz moqtrun_decode_object_loop(
    wired_moqt_hub*      hub,
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

static void moqtrun_relay_open_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    wired_span           wire);

/* A subscriber that joined AFTER this relay started (its slot never
 * opened): open its stream now, carrying the saved SUBGROUP_HEADER bytes
 * alone -- the current round's Objects are dropped for this late joiner
 * (voice is loss-tolerant; the next round appends normally, and the
 * header-only first chunk is a well-formed stream head for the client's
 * incremental decoder). */
static void moqtrun_relay_late_open(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    int                  fin) {
  if (moqtrun_late_open_skip(relay, fin)) return;
  moqtrun_relay_open_one(
      hub, sub, relay, i, wired_span_of(relay->hdr, relay->hdr_len));
}

/* Forward to sub slot i's open stream, or -- for a subscriber whose
 * stream was never opened (it subscribed after the relay started) -- open
 * one now (moqtrun_relay_late_open). */
static void moqtrun_relay_deliver_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_peer*  dst,
    wired_moqtrun_relay* relay,
    usz                  i,
    wired_span           wire,
    int                  fin) {
  if (relay->sub_stream_set[i]) {
    moqtrun_relay_forward_one(hub, dst->wt, relay, i, wire, fin);
    return;
  }
  moqtrun_relay_late_open(hub, sub, relay, i, fin);
}

_Static_assert(WIRED_MOQTRUN_MAX_SUBS <= 32, "sub_expired: one bit per sub");

static u32 moqtrun_sub_bit(usz i) { return (u32)1 << i; }

/* Sub slot i's stream on relay was reset for DELIVERY_TIMEOUT: counted,
 * and never reopened for this Subgroup. */
static void moqtrun_note_expired(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, usz i) {
  relay->sub_expired |= moqtrun_sub_bit(i);
  hub->stat_timeout_reset++;
}

/* Sub slot i is not served on relay: its peer left, or its stream timed
 * out for this Subgroup. */
static int moqtrun_relay_skips(
    const wired_moqtrun_peer* dst, const wired_moqtrun_relay* relay, usz i) {
  return !dst->in_use || (relay->sub_expired & moqtrun_sub_bit(i));
}

/* draft 8: the round's oldest Object reached the hub at born_ms; past
 * sub's OBJECT_DELIVERY_TIMEOUT its stream is reset with DELIVERY_TIMEOUT
 * and not reopened for this Subgroup. 1 when it expired. */
static int moqtrun_relay_expire(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* sub,
    wired_moqtrun_peer*      dst,
    wired_moqtrun_relay*     relay,
    usz                      i,
    u64                      born_ms) {
  if (!moqtrun_sub_late(sub, hub->live.last_now_ms - born_ms)) return 0;
  if (relay->sub_stream_set[i])
    hub->io.stream_reset(
        dst->wt, relay->sub_stream_id[i], MOQTRUN_RESET_DELIVERY_TIMEOUT);
  relay->sub_stream_set[i] = 0;
  moqtrun_note_expired(hub, relay, i);
  return 1;
}

/* wire cut to sub's End Object for relay's sub slot i (moqtrun_wire_
 * cutoff, decoding from seq0 -- the chaining state right before this
 * round). A cut that drops any bytes marks i expired on relay (10.9.1: no
 * further round reaches a subscriber past its End Object) so later
 * rounds skip it via moqtrun_relay_skips, and forces fin: this IS sub's
 * last delivery, whole.n or not. */
static wired_span moqtrun_relay_end_cut(
    wired_moqtrun_relay*     relay,
    usz                      i,
    wired_span               wire,
    moqdata_objseq           seq0,
    const wired_moqtrun_sub* sub,
    int*                     fin) {
  usz cut = moqtrun_wire_cutoff(sub, wire, 0, seq0, relay->group_id);
  if (cut == wire.n) return wire;
  relay->sub_expired |= moqtrun_sub_bit(i);
  *fin = 1;
  return wired_span_of(wire.p, cut);
}

/* One subscriber's share of a relayed round whose oldest Object arrived
 * at born_ms, cut to sub's End Object (moqtrun_relay_end_cut) when wire's
 * Objects cross it. */
static void moqtrun_relay_append_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    wired_span           wire,
    moqdata_objseq       seq0,
    int                  fin,
    u64                  born_ms) {
  wired_moqtrun_peer* dst = &hub->peers[sub->session_idx];
  if (moqtrun_relay_skips(dst, relay, i)) return;
  if (moqtrun_relay_expire(hub, sub, dst, relay, i, born_ms)) return;
  wire = moqtrun_relay_end_cut(relay, i, wire, seq0, sub, &fin);
  moqtrun_relay_deliver_one(hub, sub, dst, relay, i, wire, fin);
}

static void moqtrun_relay_append_all(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           wire,
    moqdata_objseq       seq0,
    int                  fin,
    u64                  born_ms) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (moqtrun_sub_gets(&track->subs[i], relay->group_id))
      moqtrun_relay_append_one(
          hub, &track->subs[i], relay, i, wire, seq0, fin, born_ms);
}

static int moqtrun_frag_slot_free(const wired_moqt_hub* hub, usz i) {
  const wired_moqtrun_relay* o = hub->frag_owner[i];
  return !o || !o->in_use || o->frag_idx != (i32)i;
}

static i32 moqtrun_frag_take_free(wired_moqt_hub* hub, wired_moqtrun_relay* r) {
  for (usz i = 0; i < WIRED_MOQTRUN_FRAG_POOL; i++)
    if (moqtrun_frag_slot_free(hub, i)) {
      hub->frag_owner[i] = r;
      return (i32)i;
    }
  return -1;
}

/* The pool buffer that will hold an n-byte fragment for relay: the one it
 * already holds, else a free one; -1 when n is over the limit or the pool
 * is exhausted. */
static i32 moqtrun_frag_slot_for(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, usz n) {
  if (n >= WIRED_MOQTRUN_RELAY_FRAG_MAX) return -1;
  if (relay->frag_idx >= 0) return relay->frag_idx;
  return moqtrun_frag_take_free(hub, relay);
}

/* frag_idx of a relay whose held tail was dropped: the stream's next byte
 * is mid-Object, so it must never be decoded or relayed again. */
#define MOQTRUN_FRAG_POISONED (-2)

static int moqtrun_relay_poisoned(const wired_moqtrun_relay* relay) {
  return relay->frag_idx == MOQTRUN_FRAG_POISONED;
}

/* Gives relay's fragment buffer (if any) back to the pool. */
static void moqtrun_frag_release(wired_moqtrun_relay* relay) {
  relay->frag_idx = -1;
  relay->frag_len = 0;
}

/* Teardown-side release: a poisoned relay holds no buffer, and keeps its
 * mark so it stays sunk (moqtrun_relay_sink) instead of decoding again.
 * An unused entry is skipped: its fields may never have been written, and
 * its buffer already counts as free (moqtrun_frag_slot_free). */
static void moqtrun_frag_release_unless_poisoned(wired_moqtrun_relay* relay) {
  if (relay->in_use && !moqtrun_relay_poisoned(relay))
    moqtrun_frag_release(relay);
}

/* An n-byte tail with no buffer to wait in is dropped: counted, and the
 * relay poisoned (moqtrun_relay_end_poisoned ends its subscriber side). */
static void moqtrun_frag_drop(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, usz n) {
  if (n == 0) return;
  relay->frag_idx = MOQTRUN_FRAG_POISONED;
  hub->stat_frag_drop++;
}

/* Saves the undelivered tail (bytes past the last complete Object) as the
 * relay's fragment for the next delivery, in a buffer from the hub's
 * shared pool (released once nothing is held). A tail of
 * WIRED_MOQTRUN_RELAY_FRAG_MAX bytes or more belongs to an Object over the
 * relayable limit and can never complete, and one finding the pool
 * exhausted has nowhere to wait -- both are dropped (counted on the hub)
 * and the relay is poisoned: everything after the tail starts mid-Object,
 * so the stream relays nothing more (moqtrun_relay_continue). */
static void moqtrun_relay_save_frag(
    wired_moqt_hub*      hub,
    wired_moqtrun_relay* relay,
    const u8*            p,
    usz                  n,
    u64                  born_ms) {
  i32 slot = n ? moqtrun_frag_slot_for(hub, relay, n) : -1;
  moqtrun_frag_release(relay);
  if (slot < 0) {
    moqtrun_frag_drop(hub, relay, n);
    return;
  }
  bytes_memcpy(hub->frag_pool[slot], p, n);
  relay->frag_idx = slot;
  relay->frag_len = n;
  relay->frag_ms  = born_ms;
}

/* Arrival of the first byte a delivery's whole Objects start with: the
 * held fragment's, else now.
 *
 * ponytail: decode is atomic per Object (moqdata_obj_take reads header and
 * payload together), so this hub has no observable moment between "an
 * Object's header finished" and "its payload started" -- only "this
 * Object's leading byte arrived". draft-19's "first payload byte" and
 * draft-22's "last header byte" start points collapse to that same moment
 * here; add per-Object header/payload split tracking if a version gate
 * between them is ever needed. */
static u64 moqtrun_relay_born(const wired_moqtrun_relay* r, u64 now) {
  return r->frag_len ? r->frag_ms : now;
}

/* Arrival of the tail held after a delivery whose whole Objects end at
 * off: a held fragment is under one Object, so past a whole one the tail
 * starts in this delivery (now); with none it still starts at born. */
static u64 moqtrun_tail_born(usz off, u64 now, u64 born) {
  return off ? now : born;
}

/* Object-boundary normalization (wired_moqtrun_relay's frag doc): prepends
 * the relay's held fragment to this delivery in hub->relay_scratch, finds
 * the last complete Object boundary, keeps the tail past it as the next
 * fragment, and returns the whole-Objects prefix -- the only bytes safe to
 * forward, because a forwarded round can be dropped per subscriber and a
 * dropped round must never end mid-Object. Decoding continues the
 * stream's own Object sequence (relay->seq, set from its SUBGROUP_HEADER
 * by moqtrun_relay_start), so each Object's ID counts toward the track's
 * Largest. *seq0_out receives the chaining state as it was BEFORE this
 * round's decode (relay->seq is advanced in place past it) -- a caller
 * cutting the returned span to one subscriber's End Object re-decodes
 * from this same starting point (moqtrun_wire_cutoff). */
static wired_span moqtrun_relay_normalize(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           data,
    u64*                 born_ms,
    moqdata_objseq*      seq0_out) {
  u64 now   = hub->live.last_now_ms;
  usz total = relay->frag_len + data.n;
  usz off   = 0;
  *born_ms  = moqtrun_relay_born(relay, now);
  if (relay->frag_len)
    bytes_memcpy(
        hub->relay_scratch, hub->frag_pool[relay->frag_idx], relay->frag_len);
  bytes_memcpy(hub->relay_scratch + relay->frag_len, data.p, data.n);
  *seq0_out = relay->seq;
  moqtrun_decode_object_loop(
      hub, wired_span_of(hub->relay_scratch, total), &off, &relay->seq,
      relay->group_id, track);
  moqtrun_relay_save_frag(
      hub, relay, hub->relay_scratch + off, total - off,
      moqtrun_tail_born(off, now, *born_ms));
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
 * reliable twin of stat_frag_drop), not a loss to handle. born_ms is the
 * round's oldest unflushed byte's arrival (moqtrun_relay_normalize's twin
 * for the lossy path, draft 8's "reached the hub" moment), not necessarily
 * now: a torn Object waits in the relay's fragment first. */
static void moqtrun_rel_take(
    wired_moqt_hub* hub, moqtrel_buf* rb, wired_span whole, u64 born_ms) {
  if (whole.n == 0) return;
  if (!moqtrel_append(rb, whole)) {
    hub->stat_rel_overflow++;
    return;
  }
  moqtrel_mark(rb, born_ms);
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
  moqtrun_rel_take(hub, rb, head, hub->live.last_now_ms);
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
/* 1 iff replaying relay's stream from its header stays inside sub's
 * Location Filter (9.3.1): the stream starts at or after the
 * subscription start. A stream begun before it holds Objects up to the
 * Joining Location, which a Joining Fetch covers (10.12.2.1).
 * ponytail: stream-granular -- later Objects of such a stream are not
 * sent to sub either (one Object per stream, as chat sends, loses
 * nothing); slice the ring at an Object boundary if a reliable track
 * ever sends many Objects per stream. */
static int moqtrun_rel_replay_ok(
    const wired_moqtrun_sub* sub, const wired_moqtrun_relay* relay) {
  moqctl_loc first = {relay->group_id, 0};
  return !moqctl_loc_less(first, sub->start) &&
         moqtrun_sub_wants_group(sub, relay->group_id);
}

static void moqtrun_rel_late_attach(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    moqtrel_buf*         rb,
    usz                  i,
    u64                  now_ms) {
  if (!moqtrun_rel_late_wanted(track, relay, rb, i) ||
      !moqtrun_rel_replay_ok(&track->subs[i], relay))
    return;
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
    usz                  i,
    u32                  code) {
  hub->io.stream_reset(wt, relay->sub_stream_id[i], code);
  relay->sub_stream_set[i] = 0;
  rb->subs[i].shed         = 1;
  hub->stat_rel_stall += code == 0;
  if (code == MOQTRUN_RESET_DELIVERY_TIMEOUT)
    moqtrun_note_expired(hub, relay, i);
}

/* Not a stream reset code: cursor i goes on. */
#define MOQTRUN_REL_KEEP (-1)

/* 0 for a stall, DELIVERY_TIMEOUT once cursor i's next unsent Object
 * reached the hub longer ago than the subscription's
 * OBJECT_DELIVERY_TIMEOUT (draft 8); else MOQTRUN_REL_KEEP. */
static int moqtrun_rel_expiry(
    const wired_moqtrun_track* track,
    const moqtrel_buf*         rb,
    usz                        i,
    u64                        now_ms) {
  if (moqtrel_stalled(rb, (u32)i, now_ms)) return 0;
  if (moqtrun_sub_late(&track->subs[i], moqtrel_age_ms(rb, (u32)i, now_ms)))
    return MOQTRUN_RESET_DELIVERY_TIMEOUT;
  return MOQTRUN_REL_KEEP;
}

/* The reset code to give cursor i up with, else MOQTRUN_REL_KEEP. A
 * subscription that no longer takes this stream (REQUEST_UPDATE turned
 * FORWARD off or moved its Location Filter past the Group) gets nothing
 * appended after the update (10.9.1): CANCELLED, and its cursor stops
 * pinning the ring. */
static int moqtrun_rel_give_up(
    const wired_moqtrun_track* track,
    const wired_moqtrun_relay* relay,
    const moqtrel_buf*         rb,
    usz                        i,
    u64                        now_ms) {
  if (!moqtrun_sub_gets(&track->subs[i], relay->group_id))
    return MOQTRUN_RESET_CANCELLED;
  return moqtrun_rel_expiry(track, rb, i, now_ms);
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
  int code = moqtrun_rel_give_up(track, relay, rb, i, now_ms);
  if (code != MOQTRUN_REL_KEEP) {
    moqtrun_rel_shed(hub, dst->wt, relay, rb, i, (u32)code);
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
    int                  fin,
    u64                  born_ms) {
  moqtrel_buf* rb = &hub->rel_pool[relay->rel_idx];
  moqtrun_rel_take(hub, rb, whole, born_ms);
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
    moqdata_objseq       seq0,
    int                  fin,
    u64                  born_ms) {
  if (moqtrun_relay_round_due(whole, fin))
    moqtrun_relay_append_all(hub, track, relay, whole, seq0, fin, born_ms);
  if (fin) relay->in_use = 0;
}

/* A later call on an already-relayed publisher stream: forward its
 * whole-Object bytes (moqtrun_relay_normalize) to every subscriber-side
 * stream this relay opened, and free the entry once the publisher's FIN
 * has been forwarded (the subscriber streams are closed by that same
 * round; a fragment still held at FIN time is a torn tail with no
 * continuation coming -- dropped). A ring-backed relay (rel_idx >= 0)
 * takes the reliable path instead: its bytes are retried, not dropped,
 * and its entry lives until every cursor is delivered or given up.
 * ponytail: the ring path does not cut at a draft-22 End Object mid-round
 * (seq0 unused there) -- it still gates by Group only, same as before;
 * cut it too if a reliable track's subscribers start using End Object. */
static void moqtrun_relay_forward(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           whole,
    moqdata_objseq       seq0,
    int                  fin,
    u64                  born_ms) {
  if (relay->rel_idx >= 0) {
    moqtrun_rel_continue(hub, track, relay, whole, fin, born_ms);
    return;
  }
  moqtrun_relay_continue_lossy(hub, track, relay, whole, seq0, fin, born_ms);
}

/* A poisoned relay only absorbs its publisher's bytes, so they never get
 * re-classified as a fresh stream, and frees at the publisher's FIN. */
static void moqtrun_relay_sink(wired_moqtrun_relay* relay, int fin) {
  if (fin) relay->in_use = 0;
}

/* The round that poisoned relay (moqtrun_frag_drop) ends its subscriber
 * side the way an abandoned relay stream ends (moqtrun_relay_reset_stale):
 * every subscriber stream is reset and a bound ring returned, so no
 * subscriber reads past the last whole Object. */
static void moqtrun_relay_end_poisoned(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    int                  fin) {
  if (!moqtrun_relay_poisoned(relay)) return;
  moqtrun_relay_reset_stale(hub, track, relay);
  moqtrun_relay_return_ring(hub, relay);
  moqtrun_relay_sink(relay, fin);
}

static void moqtrun_relay_continue(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           wire,
    int                  fin) {
  if (moqtrun_relay_poisoned(relay)) {
    moqtrun_relay_sink(relay, fin);
    return;
  }
  u64            born_ms;
  moqdata_objseq seq0;
  wired_span     whole =
      moqtrun_relay_normalize(hub, track, relay, wire, &born_ms, &seq0);
  /* Objects completed before the dropped tail are sound: deliver them,
   * then end the subscriber streams (moqtrun_relay_end_poisoned). */
  moqtrun_relay_forward(hub, track, relay, whole, seq0, fin, born_ms);
  moqtrun_relay_end_poisoned(hub, track, relay, fin);
}

/* Opened stream sid on relay's sub slot i reached an End Object mid-open
 * (moqtrun_relay_open_one's cut shorter than its own wire): nothing more
 * will ever be sent on it, so it is FIN'd right away and i marked expired
 * (moqtrun_relay_skips) so no later round reopens or appends to it. */
static void moqtrun_relay_open_end_hit(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    u64                  sid,
    wired_moqtrun_relay* relay,
    usz                  i,
    usz                  cut_n,
    usz                  wire_n) {
  if (cut_n == wire_n) return;
  hub->io.stream_fin(wt, sid);
  relay->sub_expired |= moqtrun_sub_bit(i);
}

/* Opens sub slot i's relay stream carrying wire, cut to sub's End Object
 * (moqtrun_hdr_cutoff) when wire still starts with its SUBGROUP_HEADER --
 * a late-open's wire is header-only (relay->hdr_len, no Objects) and the
 * cutoff passes it through unchanged. A cut that dropped bytes FINs the
 * stream right away (moqtrun_relay_open_end_hit): no further round will
 * ever reach it. Records the id for later rounds. An open failure (no
 * free send slot on that connection) leaves the slot unset: a lossy relay
 * late-opens it on a later round (moqtrun_relay_late_open), a ring-backed
 * one retries on the next drain while the ring still holds the stream's
 * start (moqtrun_rel_late_attach_all), else it gets nothing. */
static void moqtrun_relay_open_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    wired_span           wire) {
  wired_moqtrun_peer* dst = &hub->peers[sub->session_idx];
  if (!dst->in_use) return;
  wired_span cut_wire = moqtrun_hdr_cutoff(sub, wire, relay->group_id);
  wired_span out      = moqtrun_alias_splice(hub, cut_wire, sub->track_alias);
  i64        sid      = hub->io.open_uni_stream(dst->wt, out);
  if (sid < 0) {
    hub->stat_open_drop++;
    return;
  }
  moqtrun_prio_set(hub, dst->wt, sid, sub, out);
  sub->stream_count++;
  relay->sub_stream_id[i]   = (u64)sid;
  relay->sub_stream_set[i]  = 1;
  relay->sub_busy_streak[i] = 0;
  moqtrun_relay_open_end_hit(
      hub, dst->wt, (u64)sid, relay, i, cut_wire.n, wire.n);
}

static void moqtrun_relay_open_all(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           wire) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (moqtrun_sub_gets(&track->subs[i], relay->group_id))
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
  moqtrun_frag_release(relay);
  moqtrun_rel_start(
      hub, track, relay, pub_wt, pub_stream_id,
      wired_span_of(wire.p, whole_end));
  relay->sub_expired = 0;
  moqtrun_relay_save_frag(
      hub, relay, wire.p + whole_end, wire.n - whole_end,
      hub->live.last_now_ms);
  moqtrun_relay_save_hdr(relay, wire);
  moqtrun_subgroup_scan(
      wired_span_of(wire.p, whole_end), 0, &relay->seq, &relay->group_id);
  moqtrun_relay_open_all(hub, track, relay, wired_span_of(wire.p, whole_end));
  moqtrun_rel_attach_subs(hub, track, relay);
  moqtrun_relay_end_poisoned(hub, track, relay, 0);
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
/* hub (0: not a peer track) caches each whole Object of t for FETCH
 * (draft 10.12.3). A Status-only Object has no payload a fetch Object
 * could carry (11.4.4), so it reads as nonexistent there. */
static int moqtrun_cacheable(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t, u64 status) {
  return hub && t && status == MOQDATA_STATUS_NORMAL;
}

static void moqtrun_cache_obj(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    u64                  group,
    const moqdata_obj*   o) {
  if (!moqtrun_cacheable(hub, t, o->status)) return;
  moqcache_append(&hub->cache, t->cache_tag, group, o->object_id, o->payload);
}

static usz moqtrun_decode_object_loop(
    wired_moqt_hub*      hub,
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
    moqtrun_cache_obj(hub, t, group, &obj);
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
  moqtrun_decode_object_loop(0, wire, &off, seq, hdr.group_id, t);
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
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_span          data,
    usz*                whole_end,
    int                 fin) {
  usz            off = 0;
  moqdata_subhdr hdr;
  if (moqdata_subhdr_take(data, &off, &hdr) != MOQDATA_OK) return 0;
  wired_moqtrun_track* t   = moqtrun_track_by_alias(p, hdr.track_alias);
  moqdata_objseq       seq = moqdata_objseq_of(hdr.type);
  if (moqtrun_fresh_nothing_due(
          moqtrun_decode_object_loop(hub, data, &off, &seq, hdr.group_id, t),
          fin))
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
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_span          data,
    usz*                whole_end,
    int                 fin) {
  usz classify_off = 0;
  int kind         = moqdata_classify(data, &classify_off);
  if (kind != MOQDATA_STREAM_SUBGROUP) return 0;
  return moqtrun_decode_fresh_subgroup(hub, p, data, whole_end, fin);
}

/* 1 iff t is this peer's track claimed by the PUBLISH of Request ID
 * rid. */
static int moqtrun_track_pub_rid(const wired_moqtrun_track* t, u64 rid) {
  return t->in_use && t->request_id == rid;
}

/* 1 iff rid names the PUBLISH behind one of p's own tracks -- the only
 * requests this hub holds upstream (it sends no SUBSCRIBE or
 * REQUEST_UPDATE of its own toward a publisher). */
static int moqtrun_peer_pub_rid(const wired_moqtrun_peer* p, u64 rid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; i++)
    if (moqtrun_track_pub_rid(&p->tracks[i], rid)) return 1;
  return 0;
}

/* 1 iff data's FETCH_HEADER Request ID routes to a request this hub
 * knows upstream of p; a torn header routes nowhere. */
static int moqtrun_inbound_fetch_routed(
    const wired_moqtrun_peer* p, wired_span data) {
  usz at  = 0;
  u64 rid = 0;
  if (moqfetch_hdr_take(data, &at, &rid) != MOQCTL_OK) return 0;
  return moqtrun_peer_pub_rid(p, rid);
}

/* STOP_SENDING code on a peer-initiated stream the hub turns away. */
static void moqtrun_stream_stop(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 sid, u32 code) {
  if (hub->io.stream_stop) hub->io.stream_stop(p->wt, sid, code);
}

/* A fresh uni classifying as a fetch data stream (FETCH_HEADER, 11.4.4)
 * is routed by its Request ID: one naming the PUBLISH behind a track of
 * this peer is accepted against it (the hub requested no fetch or fill
 * upstream, so the stream's Objects themselves are dropped); any other
 * is asked to stop with CANCELLED. The session never closes over an
 * unroutable fetch stream. 1 when consumed. */
static int moqtrun_fresh_fetch_stream(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 sid, wired_span data) {
  usz at = 0;
  if (moqdata_classify(data, &at) != MOQDATA_STREAM_FETCH) return 0;
  if (!moqtrun_inbound_fetch_routed(p, data))
    moqtrun_stream_stop(hub, p, sid, MOQTRUN_RESET_CANCELLED);
  return 1;
}

/* A fresh SUBGROUP stream: either relayed whole as one-shot streams
 * (its FIN arrived with the data -- nothing more will follow, so a torn
 * tail has no continuation either and rides along harmlessly) or a
 * keep-open relay entry starts for the rounds still to come
 * (moqtrun_relay_start, which holds the tail back as the first
 * fragment). */
static void moqtrun_fresh_subgroup_relay(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  usz                  whole_end = 0;
  wired_moqtrun_track* track =
      moqtrun_resolve_fresh_stream_track(hub, p, data, &whole_end, fin);
  if (!track) return;
  track->up_streams++; /* checked against PUBLISH_DONE's Stream Count */
  if (fin) {
    moqtrun_relay_object(hub, track, data);
    return;
  }
  moqtrun_relay_start(hub, track, p->wt, stream_id, data, whole_end);
}

/* A publisher stream seen for the first time: an inbound fetch stream
 * routes by its Request ID, a SUBGROUP stream resolves its track from
 * the header and relays. Padding streams, other classifications, and
 * unknown Track Aliases are discarded: classification-level session
 * closes are the sess layer's job. */
static void moqtrun_dispatch_fresh_stream(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  if (moqtrun_fresh_fetch_stream(hub, p, stream_id, data)) return;
  moqtrun_fresh_subgroup_relay(hub, p, stream_id, data, fin);
}

/* sid is the hub's own, opened control stream (the legacy bidi the
 * client writes back on; a failed open never aliases a client id). */
static int moqtrun_rx_is_own_ctl(const wired_moqtrun_peer* p, u64 sid) {
  return p->ctl_opened && sid == p->control_stream_id;
}

/* draft-19 3.3: control streams stay open for the session's life -- a
 * transport-level end (FIN, RESET_STREAM, STOP_SENDING) of either one
 * closes the session with PROTOCOL_VIOLATION. */
static void moqtrun_ctl_gone(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  moqsess_step(&p->sess, MOQSESS_EV_CTRL_CLOSED);
  moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
}

/* Dispatches data as control-stream bytes arriving on sid: the hub's
 * own (legacy bidi) stream reassembles in ctl_asm, a distinct client
 * control stream in peer_ctl_asm -- before acceptance both can carry
 * bytes in the same session, so they never share a reassembly. */
static void moqtrun_ctl_rx(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  p->rx_sid = sid;
  p->rx     = moqtrun_rx_is_own_ctl(p, sid) ? &p->ctl_asm : &p->peer_ctl_asm;
  moqtrun_dispatch_ctl_stream(hub, p, (usz)(p - hub->peers), data);
  p->rx = 0;
  if (fin) moqtrun_ctl_gone(hub, p);
}

/* draft-19 3.3: the first client control stream wins; a second one
 * closes the session. On adoption the delivery's remaining bytes
 * dispatch as control messages (the SETUP itself first). */
static void moqtrun_ctl_adopt_rx(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  if (p->peer_ctl_set) {
    moqtrun_second_ctl(hub, p);
    return;
  }
  p->peer_ctl_set       = 1;
  p->peer_ctl_stream_id = sid;
  moqtrun_ctl_rx(hub, p, sid, data, fin);
}

/* draft-19 3.4/10.1: a fresh uni whose Stream Type is 0x2F00 is the
 * client's control stream. The Stream Type varint and the SETUP
 * message's own Type field are the SAME varint (compare FETCH_HEADER
 * 11.4.4, which is read the same way by moqfetch_hdr_take on the
 * unconsumed data) -- it is not repeated, so the classifying read must
 * not be consumed before the SETUP decode gets to see it. 1 when
 * consumed. */
static int moqtrun_fresh_uni_ctl(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  usz at = 0;
  if (moqdata_classify(data, &at) != MOQDATA_STREAM_CONTROL) return 0;
  moqtrun_ctl_adopt_rx(hub, p, sid, data, fin);
  return 1;
}

/* ============== pre-establishment hold (draft-19 3.3) ============== */

/* Streams are held while SETUP is incomplete: a token session until
 * both directions are done; a legacy session only until the hub's own
 * SETUP went out (its browser clients never send one back, and their
 * requests must flow regardless). */
static int moqtrun_hold_gate(const wired_moqtrun_peer* p) {
  return p->legacy ? !p->ctl_opened : !moqsess_established(&p->sess);
}

/* One held record: 8-byte stream id + 2-byte length + 1-byte fin. */
#define MOQTRUN_HOLD_HDR 11

static usz moqtrun_hold_rec_len(const wired_moqtrun_peer* p, usz at) {
  return (((usz)p->hold[at + 8] << 8) | p->hold[at + 9]) + MOQTRUN_HOLD_HDR;
}

/* An earlier delivery of sid is already held: later ones follow it into
 * the log whatever their bytes look like (mid-stream bytes must never
 * be re-classified). */
static int moqtrun_hold_has(const wired_moqtrun_peer* p, u64 sid) {
  for (usz at = 0; at < p->hold_len; at += moqtrun_hold_rec_len(p, at))
    if (be_get_be64(p->hold + at) == sid) return 1;
  return 0;
}

static void moqtrun_hold_put(
    wired_moqtrun_peer* p, u64 sid, wired_span data, int fin) {
  u8* at = p->hold + p->hold_len;
  be_put_be64(at, sid);
  at[8]  = (u8)(data.n >> 8);
  at[9]  = (u8)data.n;
  at[10] = (u8)(fin != 0);
  bytes_memcpy(at + MOQTRUN_HOLD_HDR, data.p, data.n);
  p->hold_len += MOQTRUN_HOLD_HDR + data.n;
}

/* Holds one delivery for replay. One that does not fit is lost: a
 * request stream is reset EXCESSIVE_LOAD now -- before establishment,
 * never after (3.3.4) -- while an Object stream is silently dropped
 * (only its own pre-SETUP bytes are lost). */
static void moqtrun_hold_push(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  if (p->hold_len + MOQTRUN_HOLD_HDR + data.n <= sizeof p->hold) {
    moqtrun_hold_put(p, sid, data, fin);
    return;
  }
  if ((sid & 3) == 0)
    hub->io.stream_reset(p->wt, sid, MOQTRUN_RESET_EXCESSIVE_LOAD);
}

static void moqtrun_dispatch_other(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);

static usz moqtrun_hold_replay_one(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz at) {
  usz n = moqtrun_hold_rec_len(p, at) - MOQTRUN_HOLD_HDR;
  moqtrun_dispatch_other(
      hub, p, be_get_be64(p->hold + at),
      wired_span_of(p->hold + at + MOQTRUN_HOLD_HDR, n), p->hold[at + 10]);
  return MOQTRUN_HOLD_HDR + n;
}

static int moqtrun_hold_ready(const wired_moqtrun_peer* p) {
  return p->in_use && p->hold_len != 0 && !moqtrun_hold_gate(p);
}

static int moqtrun_hold_more(const wired_moqtrun_peer* p, usz at, usz n) {
  return at < n && !p->closing;
}

/* Replays every held delivery in arrival order once the gate lifts.
 * hold_len drops to 0 first, so a replayed record can never re-hold;
 * the records replay straight out of the log (nothing appends while
 * the gate is open). A session closing mid-replay drops the rest. */
static void moqtrun_hold_replay(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  usz at = 0;
  usz n  = p->hold_len;
  if (!moqtrun_hold_ready(p)) return;
  p->hold_len = 0;
  while (moqtrun_hold_more(p, at, n)) at += moqtrun_hold_replay_one(hub, p, at);
}

/* The control/hold/data decision for a FRESH uni delivery. */
static void moqtrun_dispatch_uni_fresh(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  if (moqtrun_fresh_uni_ctl(hub, p, stream_id, data, fin)) return;
  if (moqtrun_hold_gate(p)) {
    moqtrun_hold_push(hub, p, stream_id, data, fin);
    return;
  }
  moqtrun_dispatch_fresh_stream(hub, p, stream_id, data, fin);
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
  if (moqtrun_hold_has(p, stream_id)) {
    moqtrun_hold_push(hub, p, stream_id, data, fin);
    return;
  }
  moqtrun_dispatch_uni_fresh(hub, p, stream_id, data, fin);
}

/* ===================== request-stream slots ===================== */

/* No Request ID read: matches no subscription or track (Request IDs are
 * at most 2^62-1, draft 10.1). */
#define MOQTRUN_RID_NONE (~(u64)1)

static int moqtrun_req_is(
    const wired_moqtrun_req* q, const wired_wt_session* s, u64 stream_id) {
  return q->in_use && q->wt == s && q->stream_id == stream_id;
}

static wired_moqtrun_req* moqtrun_req_find(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 stream_id) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    if (moqtrun_req_is(&hub->reqs[i], s, stream_id)) return &hub->reqs[i];
  return 0;
}

/* A free slot no subscription still owes a NAMESPACE_DONE for
 * (wired_moqtrun_req.ns_seen). */
static int moqtrun_req_slot_free(const wired_moqt_hub* hub, usz i) {
  return !hub->reqs[i].in_use && !moqtrun_disc_held(hub, i);
}

static wired_moqtrun_req* moqtrun_req_free_slot(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    if (moqtrun_req_slot_free(hub, i)) return &hub->reqs[i];
  return 0;
}

/* A peer-opened bidi stream: the hub is always the server, and RFC 9000
 * 2.1 numbers client-initiated bidi streams 0 mod 4. Needs the io's
 * reply op to answer on it. */
static int moqtrun_req_stream_ok(const wired_moqt_hub* hub, u64 stream_id) {
  return (stream_id & 3) == 0 && hub->io.stream_reply_open != 0;
}

static wired_moqtrun_req* moqtrun_req_open(
    wired_moqtrun_req* q, wired_wt_session* s, u64 stream_id) {
  q->in_use          = 1;
  q->wt              = s;
  q->stream_id       = stream_id;
  q->kind            = 0;
  q->request_id      = MOQTRUN_RID_NONE;
  q->opened          = 0;
  q->in.n            = 0;
  q->in.at           = 0;
  q->in.skip         = 0;
  q->send_lens[0]    = 0;
  q->send_lens[1]    = 0;
  q->armed_idx       = 0;
  q->goaway          = 0;
  q->live            = 0;
  q->fin_in          = 0;
  q->fin_out         = 0;
  q->done_pending    = 0;
  q->done_status     = 0;
  q->done_count      = 0;
  q->ns_len          = 0;
  q->ns_seen         = 0;
  q->pending_updates = 0;
  bytes_memset(q->attempted_tag, 0, sizeof q->attempted_tag);
  q->pub_origin_rid = 0;
  q->pub_track_tag  = 0;
  q->pub_alias      = 0;
  q->forward_zero   = 0;
  q->group_order    = 0;
  return q;
}

static int moqtrun_req_owned(const wired_moqtrun_req* q, wired_wt_session* s) {
  return q->in_use && q->wt == s;
}

static usz moqtrun_req_count(const wired_moqt_hub* hub, wired_wt_session* s) {
  usz n = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    n += (usz)moqtrun_req_owned(&hub->reqs[i], s);
  return n;
}

/* A fresh slot for a new request stream of s, or -- s at its share of the
 * pool, or the pool full -- the stream is reset with EXCESSIVE_LOAD and 0
 * returned. */
static wired_moqtrun_req* moqtrun_req_admit(
    wired_moqt_hub* hub, wired_wt_session* s, u64 stream_id) {
  wired_moqtrun_req* q =
      moqtrun_req_count(hub, s) < WIRED_MOQTRUN_MAX_REQS_PER_SESSION
          ? moqtrun_req_free_slot(hub)
          : 0;
  if (q) return moqtrun_req_open(q, s, stream_id);
  hub->io.stream_reset(s, stream_id, MOQTRUN_RESET_EXCESSIVE_LOAD);
  return 0;
}

/* stream_id's request slot, else a fresh one -- but not for a delivery
 * with no bytes (a FIN trailing a request whose slot is already freed). */
static wired_moqtrun_req* moqtrun_req_for(
    wired_moqt_hub* hub, wired_wt_session* s, u64 stream_id, wired_span data) {
  wired_moqtrun_req* q = moqtrun_req_find(hub, s, stream_id);
  if (q) return q;
  if (data.n == 0) return 0;
  return moqtrun_req_admit(hub, s, stream_id);
}

/* ----- request completion (draft 3.3.2) ----- */

/* Answered without establishing anything: the request is complete. */
static int moqtrun_req_answered(const wired_moqtrun_req* q) {
  return q->kind && !q->live;
}

/* The peer ended its side before sending a whole request. */
static int moqtrun_req_orphan(const wired_moqtrun_req* q) {
  return q->fin_in && !q->kind;
}

static int moqtrun_req_ending(const wired_moqtrun_req* q) {
  return moqtrun_req_answered(q) || moqtrun_req_orphan(q);
}

/* 1 iff the hub may end its side now: the request is complete and its
 * answer has left the queue. */
static int moqtrun_req_may_end(const wired_moqtrun_req* q) {
  return !q->fin_out && moqtrun_req_ending(q) &&
         q->send_lens[q->armed_idx ^ 1] == 0;
}

/* Ends the hub's side: a FIN after the answer, or -- nothing was ever
 * sent (an orphan, or a request that could not be decoded) -- a reset
 * with INTERNAL_ERROR (draft 3.3.4). 1 when accepted. */
static int moqtrun_req_end_out(wired_moqt_io* io, wired_moqtrun_req* q) {
  if (q->opened) return io->stream_fin(q->wt, q->stream_id) > 0;
  return io->stream_reset(q->wt, q->stream_id, MOQTRUN_RESET_INTERNAL_ERROR) >
         0;
}

static int moqtrun_req_both_ended(const wired_moqtrun_req* q) {
  return q->fin_in && q->fin_out;
}

/* Sends what is queued, ends the hub's side once the request is complete,
 * and frees the slot when both sides have ended. Replies this small are
 * copied by the transport (srvrun.h: only payloads past its 64 KiB
 * staging are held as views), so freeing the slot never strands bytes. A
 * refused send or end is retried on the next delivery or tick. */
static void moqtrun_req_settle(wired_moqt_io* io, wired_moqtrun_req* q) {
  moqtrun_req_flush(io, q->wt, q);
  if (moqtrun_req_may_end(q)) q->fin_out = moqtrun_req_end_out(io, q);
  q->in_use = !moqtrun_req_both_ended(q);
}

/* A hub-opened PUBLISH request slot (SUBSCRIBE_TRACKS's own doc) settles
 * by its own rule (moqtrun_pubst_recv's doc): REQUEST_OK/REQUEST_ERROR,
 * never moqtrun_req_settle's client-request completion/FIN logic, whose
 * "answered without establishing" reading of kind+!live would otherwise
 * misfire while this slot is simply awaiting its one reply. */
static int moqtrun_reqs_tick_settles(const wired_moqtrun_req* q) {
  return q->in_use && !q->pub_origin_rid;
}

/* Pushes owed namespace changes, syncs SUBSCRIBE_TRACKS against every
 * published track, then settles every client-request stream. */
static void moqtrun_reqs_tick(wired_moqt_hub* hub) {
  moqtrun_disc_sync(hub);
  moqtrun_subtracks_sync(hub);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    if (moqtrun_reqs_tick_settles(&hub->reqs[i]))
      moqtrun_req_settle(&hub->io, &hub->reqs[i]);
}

/* 1 iff q's first message is still incomplete but its Type is already
 * readable and is no request type. */
static int moqtrun_req_bad_open(const wired_moqtrun_req* q) {
  usz at   = 0;
  u64 type = 0;
  if (q->kind || !moqvi_take(moqtrun_asm_rest(&q->in), &at, &type)) return 0;
  return !moqtrun_req_is_first(type);
}

/* draft 3.3: the opening Type is judged as soon as it is readable -- Object
 * data sent on a bidi stream need never complete a control message. */
static void moqtrun_req_check_open(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  if (!moqtrun_req_bad_open(p->req)) return;
  moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
}

static void moqtrun_req_cancel(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_req* q);

/* draft-18 6.1 names exactly these two as cancellable by FIN. */
static int moqtrun_req_fin_kind(u64 kind) {
  return kind == MOQNS_T_SUBSCRIBE_NAMESPACE ||
         kind == MOQCTL_T_SUBSCRIBE_TRACKS;
}

/* draft-18 6.1: a FIN cancels a live SUBSCRIBE_NAMESPACE or
 * SUBSCRIBE_TRACKS; draft-19 3.3.2 made every FIN a plain half-close. */
static int moqtrun_req_fin_cancels(
    const wired_moqtrun_peer* p, const wired_moqtrun_req* q) {
  return (moqver_caps(p->ver) & MOQVER_CAP_FIN_CANCEL_NS) && q->live &&
         moqtrun_req_fin_kind(q->kind);
}

/* Records the peer's FIN; on drafts where it is a cancellation the
 * request is cancelled as a RESET_STREAM would (moqtrun_req_cancel). */
static void moqtrun_req_note_fin(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_req* q, int fin) {
  q->fin_in |= fin;
  if (fin && moqtrun_req_fin_cancels(p, q)) moqtrun_req_cancel(hub, p, q);
}

static void moqtrun_dispatch_req_stream(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  wired_moqtrun_req* q = moqtrun_req_for(hub, p->wt, stream_id, data);
  if (!q) return;
  p->req = q;
  moqtrun_dispatch_ctl_stream(hub, p, (usz)(p - hub->peers), data);
  moqtrun_req_check_open(hub, p);
  p->req = 0;
  moqtrun_req_note_fin(hub, p, q, fin);
  moqtrun_reqs_tick(hub);
}

/* draft-19 3.3 leniency: a fresh client bidi whose first varint is
 * SETUP's Type is the client control stream, not a request stream. */
static int moqtrun_bidi_is_setup(
    wired_moqt_hub* hub, wired_wt_session* s, u64 sid, wired_span data) {
  usz at = 0;
  u64 t  = 0;
  if (moqtrun_req_find(hub, s, sid)) return 0;
  return moqvi_take(data, &at, &t) && t == MOQCTL_T_SETUP;
}

/* The control/hold/request decision for a FRESH bidi delivery. */
static void moqtrun_dispatch_bidi_fresh(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  if (moqtrun_bidi_is_setup(hub, p->wt, stream_id, data)) {
    moqtrun_ctl_adopt_rx(hub, p, stream_id, data, fin);
    return;
  }
  if (moqtrun_hold_gate(p)) {
    moqtrun_hold_push(hub, p, stream_id, data, fin);
    return;
  }
  moqtrun_dispatch_req_stream(hub, p, stream_id, data, fin);
}

/* draft 10.9: REQUEST_OK (empty params for a PUBLISH_OK) or REQUEST_ERROR,
 * the first and only message the SUBSCRIBE_TRACKS-generated PUBLISH's
 * receiver sends back. Reassembled through q->in exactly like a client
 * request's reply (moqtrun_asm_push/pop) since a real transport may
 * deliver it split; anything else is ignored. REQUEST_OK marks the slot
 * live (the subscription this PUBLISH established -- stays open, continuing
 * past a later SUBSCRIBE_TRACKS cancel per 1784-1787/T-10); REQUEST_ERROR
 * frees it at once (nothing to continue). */
/* 1 iff type/body is a well-formed REQUEST_ERROR. */
static int moqtrun_pubst_is_error(u64 type, wired_span body) {
  usz                  off = 0;
  moqctl_request_error e;
  if (type != MOQCTL_T_REQUEST_ERROR) return 0;
  return moqctl_request_error_take(body, &off, &e) == MOQCTL_OK;
}

static void moqtrun_pubst_route(
    wired_moqtrun_req* q, u64 type, wired_span body) {
  if (type == MOQCTL_T_REQUEST_OK) q->live = 1;
  if (moqtrun_pubst_is_error(type, body)) q->in_use = 0;
}

static void moqtrun_pubst_recv(wired_moqtrun_req* q, wired_span data) {
  u64        type = 0;
  wired_span body = {0, 0};
  moqtrun_asm_push(&q->in, &data);
  if (moqtrun_asm_pop(&q->in, &type, &body) == MOQCTL_OK)
    moqtrun_pubst_route(q, type, body);
}

/* A hub-opened PUBLISH request slot (SUBSCRIBE_TRACKS's own doc): routed
 * here instead of moqtrun_req_stream_ok's client-bidi parity test, which
 * would otherwise misclassify it (a hub-opened stream_id has no fixed
 * parity in this layer's own test stubs). */
static wired_moqtrun_req* moqtrun_pubst_slot(
    wired_moqt_hub* hub, wired_wt_session* s, u64 stream_id) {
  wired_moqtrun_req* q = moqtrun_req_find(hub, s, stream_id);
  return q && q->pub_origin_rid ? q : 0;
}

/* 1 iff stream_id is a hub-opened PUBLISH slot (handled, pq's own doc). */
static int moqtrun_dispatch_pubst(
    wired_moqt_hub*   hub,
    wired_wt_session* s,
    u64               stream_id,
    wired_span        data,
    int               fin) {
  wired_moqtrun_req* pq = moqtrun_pubst_slot(hub, s, stream_id);
  if (!pq) return 0;
  moqtrun_pubst_recv(pq, data);
  pq->fin_in |= fin;
  return 1;
}

/* With request streams on, a peer-opened bidi stream is never Object data
 * (draft 3.3: Objects travel on unidirectional streams only). */
static void moqtrun_dispatch_client_bidi(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  if (!moqtrun_req_stream_ok(hub, stream_id)) {
    moqtrun_dispatch_data_stream(hub, p, stream_id, data, fin);
    return;
  }
  if (moqtrun_hold_has(p, stream_id)) {
    moqtrun_hold_push(hub, p, stream_id, data, fin);
    return;
  }
  moqtrun_dispatch_bidi_fresh(hub, p, stream_id, data, fin);
}

/* A hub-opened PUBLISH slot's stream_id is routed to its own reply parser
 * (moqtrun_dispatch_pubst) before the client-bidi classification below,
 * which would otherwise misread it (moqtrun_pubst_slot's own doc). */
static void moqtrun_dispatch_other(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  if (moqtrun_dispatch_pubst(hub, p->wt, stream_id, data, fin)) return;
  moqtrun_dispatch_client_bidi(hub, p, stream_id, data, fin);
}

/* ===================== public entry points ===================== */

/* sid carries control bytes: the hub's own control stream or the
 * accepted client control stream. */
static int moqtrun_rx_on_ctl(const wired_moqtrun_peer* p, u64 sid) {
  return moqtrun_rx_is_own_ctl(p, sid) ||
         (p->peer_ctl_set && sid == p->peer_ctl_stream_id);
}

void wired_moqt_on_stream_data(
    void*             app_ctx,
    wired_wt_session* s,
    u64               stream_id,
    wired_span        data,
    int               fin) {
  wired_moqt_hub*     hub = (wired_moqt_hub*)app_ctx;
  wired_moqtrun_peer* p   = moqtrun_find_by_wt(hub, s);
  if (!p) return;
  if (moqtrun_rx_on_ctl(p, stream_id))
    moqtrun_ctl_rx(hub, p, stream_id, data, fin);
  else
    moqtrun_dispatch_other(hub, p, stream_id, data, fin);
  moqtrun_hold_replay(hub, p);
  moqtrun_pubdone_sweep(hub);
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
    wired_moqtrun_peer* p, wired_span data, moqctl_loc* loc) {
  usz       off = 0;
  moqdg_obj obj;
  if (moqdg_take(data, &off, &obj) != MOQDATA_OK) return 0;
  wired_moqtrun_track* t = moqtrun_track_by_alias(p, obj.track_alias);
  moqtrun_track_note(t, obj.group_id, obj.object_id);
  *loc = moqctl_loc_of(obj.group_id, obj.object_id);
  return t;
}

/* One subscriber's copy: the same bytes, only the Track Alias re-spelled
 * to the subscriber's own (moqtrun_alias_splice; usually a no-op). An
 * accepted queue counts on stat_dg_sent, a refusal on
 * stat_dg_drop -- and that copy is simply gone (no retransmission, no
 * busy streak: the next audio frame arrives in ~20ms anyway). */
static void moqtrun_dg_to_one(
    wired_moqt_hub* hub, const wired_moqtrun_sub* sub, wired_span data) {
  wired_moqtrun_peer* dst = &hub->peers[sub->session_idx];
  if (!dst->in_use) return;
  wired_span out = moqtrun_alias_splice(hub, data, sub->track_alias);
  if (hub->io.send_datagram(dst->wt, out) == 1)
    hub->stat_dg_sent++;
  else
    hub->stat_dg_drop++;
}

/* Stateless fan-out to every active subscriber of the track whose
 * Location Filter takes the Object at loc -- the datagram twin of
 * moqtrun_relay_object. A deactivated (closed) subscription is skipped;
 * late subscribers get nothing retroactively. Sent the moment it arrives,
 * a datagram is never past an OBJECT_DELIVERY_TIMEOUT (draft 8). */
static void moqtrun_dg_fanout(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* track,
    wired_span                 data,
    moqctl_loc                 loc) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (moqtrun_sub_gets_loc(&track->subs[i], loc))
      moqtrun_dg_to_one(hub, &track->subs[i], data);
}

void wired_moqt_on_datagram(
    void* app_ctx, wired_wt_session* s, wired_span data) {
  wired_moqt_hub*     hub = (wired_moqt_hub*)app_ctx;
  wired_moqtrun_peer* p   = moqtrun_find_by_wt(hub, s);
  if (!moqtrun_dg_ready(hub, p)) return;
  moqctl_loc           loc   = {0, 0};
  wired_moqtrun_track* track = moqtrun_dg_track(p, data, &loc);
  /* Malformed or unknown-alias: dropped whole. Draft 11.3.1 says an
   * invalid Type MUST close the session (PROTOCOL_VIOLATION), but this
   * hub's io table has no close operation -- counting is the closest. */
  if (!track) {
    hub->stat_dg_bad++;
    return;
  }
  moqtrun_dg_fanout(hub, track, data, loc);
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

/* Any Request ID: a closed session drops all of a peer's subscriptions. */
#define MOQTRUN_RID_ANY (~(u64)0)

/* sub is held by peer index idx under Request ID rid (or any rid). */
static int moqtrun_sub_is_req(const wired_moqtrun_sub* sub, usz idx, u64 rid) {
  return moqtrun_sub_is_peer(sub, idx) &&
         (rid == MOQTRUN_RID_ANY || sub->request_id == rid);
}

/* Deactivate track t's subscription entries held by peer index idx under
 * Request ID rid. */
static void moqtrun_track_drop_sub(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz idx, u64 rid) {
  for (usz si = 0; si < WIRED_MOQTRUN_MAX_SUBS; si++) {
    if (!moqtrun_sub_is_req(&t->subs[si], idx, rid)) continue;
    t->subs[si].active = 0;
    moqtrun_relays_clear_sub(hub, t, si);
  }
}

/* Applied to one track with a peer index and an argument. */
typedef void (*moqtrun_track_fn)(
    wired_moqt_hub*, wired_moqtrun_track*, usz idx, u64 arg);

static void moqtrun_peer_each_track(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* q,
    moqtrun_track_fn    fn,
    usz                 idx,
    u64                 arg) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    if (q->tracks[t].in_use) fn(hub, &q->tracks[t], idx, arg);
}

/* The hub's own tracks (blob and live) count too: e.g. they forget a
 * closed peer index, so a reconnect landing in the same slot is served
 * afresh, not mistaken for the dead peer. */
static void moqtrun_hub_each_track(
    wired_moqt_hub* hub, moqtrun_track_fn fn, usz idx, u64 arg) {
  if (hub->blob_track.in_use) fn(hub, &hub->blob_track, idx, arg);
  if (hub->live.track.in_use) fn(hub, &hub->live.track, idx, arg);
}

/* fn on every in-use track: every peer's and the hub's own. */
static void moqtrun_each_track(
    wired_moqt_hub* hub, moqtrun_track_fn fn, usz idx, u64 arg) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (hub->peers[i].in_use)
      moqtrun_peer_each_track(hub, &hub->peers[i], fn, idx, arg);
  moqtrun_hub_each_track(hub, fn, idx, arg);
}

/* Deactivate every subscription held for peer index idx under Request ID
 * rid. */
static void moqtrun_drop_peer_subs(wired_moqt_hub* hub, usz idx, u64 rid) {
  moqtrun_each_track(hub, moqtrun_track_drop_sub, idx, rid);
}

/* A closed session's request streams go back to the pool. */
static void moqtrun_reqs_drop(wired_moqt_hub* hub, wired_wt_session* s) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    if (moqtrun_req_owned(&hub->reqs[i], s)) hub->reqs[i].in_use = 0;
}

/* A closed publisher's held fragments can never complete: their buffers
 * go back to the pool (the relay entries themselves stay -- see below). */
static void moqtrun_peer_frags_release(wired_moqtrun_peer* p) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++)
      moqtrun_frag_release_unless_poisoned(&p->tracks[t].relays[r]);
}

static void moqtrun_peer_tracks_ended(
    wired_moqt_hub* hub, wired_moqtrun_peer* p);

void wired_moqt_on_session_close(void* app_ctx, wired_wt_session* s) {
  wired_moqt_hub*     hub = (wired_moqt_hub*)app_ctx;
  wired_moqtrun_peer* p   = moqtrun_find_by_wt(hub, s);
  if (!p) return;
  moqtrun_peer_tracks_ended(hub, p);
  moqtrun_drop_peer_subs(hub, (usz)(p - hub->peers), MOQTRUN_RID_ANY);
  moqtrun_reqs_drop(hub, s);
  moqtrun_fetches_drop(hub, s);
  /* The leaver's own rings return now (moqtrun_rel_drop_ring's doc); its
   * relay entries stay untouched so a later re-claim can still reset the
   * subscriber streams they record (moqtrun_track_reset_stale_relays). */
  moqtrun_peer_drop_rings(hub, p);
  moqtrun_peer_frags_release(p);
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++) {
    moqtrun_fills_upstream_gone(hub, p->tracks[t].cache_tag);
    moqtrun_track_cache_drop(hub, &p->tracks[t]);
  }
  p->in_use = 0;
  moqtrun_reqs_tick(hub); /* its namespaces are withdrawn (10.18) */
}

/* A cancelled SUBSCRIBE's recorded name stops matching (no name is longer
 * than WIRED_MOQTRUN_MAX_NAME), so a REPUBLISH does not re-attach it
 * (moqtrun_reattach_subs). */
static void moqtrun_sub_names_forget(wired_moqtrun_peer* p, u64 rid) {
  for (usz i = 0; i < p->sub_names_n; i++)
    if (p->sub_state[i].request_id == rid)
      p->sub_name_lens[i] = WIRED_MOQTRUN_MAX_NAME + 1;
}

static int moqtrun_track_is_req(const wired_moqtrun_track* t, u64 rid) {
  return t->in_use && t->request_id == rid;
}

/* A cancelled PUBLISH withdraws its track. */
static void moqtrun_peer_unpublish(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 rid) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    if (moqtrun_track_is_req(&p->tracks[t], rid))
      moqtrun_track_retire(hub, &p->tracks[t]);
}

/* draft-ietf-moq-transport-19 3.3.3: the request is cancelled -- its
 * subscription or track goes, the hub's own side is reset with CANCELLED
 * unless it already ended, answered or not, and the slot is freed. A
 * PUBLISH_NAMESPACE or SUBSCRIBE_NAMESPACE lives in the slot itself, so
 * freeing it withdraws the namespace (6.2) or stops the pushes (6.1); the
 * caller's moqtrun_reqs_tick sends the NAMESPACE_DONEs owed. */
static void moqtrun_req_cancel(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_req* q) {
  moqtrun_pubdone_flush(hub, p, q->request_id);
  moqtrun_drop_peer_subs(hub, (usz)(p - hub->peers), q->request_id);
  moqtrun_sub_names_forget(p, q->request_id);
  moqtrun_peer_unpublish(hub, p, q->request_id);
  moqtrun_fetches_cancel(hub, p->wt, q->request_id);
  if (!q->fin_out)
    hub->io.stream_reset(p->wt, q->stream_id, MOQTRUN_RESET_CANCELLED);
  q->in_use = 0;
}

/* A reset publisher stream sends no more bytes: a fragment its relay
 * holds can never complete, so its buffer goes back to the pool. */
static void moqtrun_stream_frag_release(wired_moqtrun_peer* p, u64 stream_id) {
  wired_moqtrun_track* t;
  wired_moqtrun_relay* r = moqtrun_peer_relay_by_stream(p, stream_id, &t);
  if (r) moqtrun_frag_release_unless_poisoned(r);
}

/* A reset control stream kills the session (draft-19 3.3); a reset
 * request stream cancels its request; a reset publisher stream frees
 * its held fragment. */
static void moqtrun_reset_dispatch(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_req*  q,
    u64                 stream_id) {
  if (moqtrun_rx_on_ctl(p, stream_id)) {
    moqtrun_ctl_gone(hub, p);
    return;
  }
  if (q)
    moqtrun_req_cancel(hub, p, q);
  else
    moqtrun_stream_frag_release(p, stream_id);
}

void wired_moqt_on_stream_reset(
    void*             app_ctx,
    wired_wt_session* s,
    u64               stream_id,
    int               mapped,
    u32               app_error_code) {
  wired_moqt_hub*     hub = (wired_moqt_hub*)app_ctx;
  wired_moqtrun_peer* p   = moqtrun_find_by_wt(hub, s);
  wired_moqtrun_req*  q   = moqtrun_req_find(hub, s, stream_id);
  (void)mapped;
  (void)app_error_code;
  if (!p) return;
  moqtrun_fetches_stream_gone(hub, s, stream_id);
  moqtrun_reset_dispatch(hub, p, q, stream_id);
  moqtrun_reqs_tick(hub);
}

/* ===================== PUBLISH_DONE (draft 10.11) ===================== */

static int moqtrun_encode_publish_done(
    wired_mspan buf, usz* off, const void* m) {
  return moqctl_publish_done_encode(buf, off, m);
}

static int moqtrun_req_holds(const wired_moqtrun_req* q, u64 rid) {
  return q->kind == MOQCTL_T_SUBSCRIBE && q->live && q->request_id == rid;
}

static int moqtrun_req_sub_of(
    const wired_moqtrun_req* q, const wired_moqtrun_peer* p, u64 rid) {
  return !p->closing && moqtrun_req_owned(q, p->wt) &&
         moqtrun_req_holds(q, rid);
}

/* The request stream of p carrying its live subscription rid, else 0 --
 * also for a session the hub is closing (nothing more goes to it). */
static wired_moqtrun_req* moqtrun_sub_req(
    wired_moqt_hub* hub, const wired_moqtrun_peer* p, u64 rid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    if (moqtrun_req_sub_of(&hub->reqs[i], p, rid)) return &hub->reqs[i];
  return 0;
}

/* draft-ietf-moq-transport-19 3.3.4 reset code for the streams of a
 * subscription ended with PUBLISH_DONE status: GOING_AWAY for a drain,
 * CANCELLED otherwise (track ended, update failed). */
static u32 moqtrun_done_reset_code(u64 status) {
  return status == MOQCTL_DONE_GOING_AWAY ? MOQTRUN_RESET_GOING_AWAY
                                          : MOQTRUN_RESET_CANCELLED;
}

/* Every relay stream of slot si of t is reset with code. */
static void moqtrun_sub_reset_streams(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz si, u32 code) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++)
    if (t->relays[r].in_use)
      moqtrun_relay_reset_one_sub(hub, t, &t->relays[r], si, code);
}

/* Subscription s (slot of track t; t 0 when s is state kept for a gone
 * publisher) gets nothing more: draft 10.11, every stream opened for it
 * is closed (reset with code) before its PUBLISH_DONE. */
static void moqtrun_sub_stop(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    wired_moqtrun_sub*   s,
    u32                  code) {
  if (t) {
    moqtrun_sub_reset_streams(hub, t, (usz)(s - t->subs), code);
    moqtrun_relays_clear_sub(hub, t, (usz)(s - t->subs));
  }
  s->active = 0;
}

/* Queues PUBLISH_DONE(status, count) as q's last message and FINs it
 * (3.3.2). */
static void moqtrun_done_emit(
    wired_moqtrun_peer* p, wired_moqtrun_req* q, u64 status, u64 count) {
  u8                  msg[WIRED_MOQTRUN_CTL_REPLY_MAX];
  moqctl_publish_done d = {0};
  d.status_code         = moqctl_publish_done_for(p->ver, status);
  d.stream_count        = count;
  usz n                 = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_PUBLISH_DONE,
      moqtrun_encode_publish_done, &d);
  moqtrun_req_queue(q, wired_span_of(msg, n));
  q->live = 0;
}

/* Ends subscription s of peer p, carried by request stream q: PUBLISH_DONE
 * status is q's last message, then the hub FINs it (3.3.2) once sent, and
 * a rejoining publisher does not revive it. While a fill of s is still
 * held unopened the message waits -- no stream may open after
 * PUBLISH_DONE -- and goes out when that fill gets its stream
 * (moqtrun_fill_opened); a cancel drops the held fill and the wait. */
static void moqtrun_sub_done(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_req*   q,
    wired_moqtrun_track* t,
    wired_moqtrun_sub*   s,
    u64                  status) {
  u64 count = s->stream_count;
  u64 rid   = s->request_id;
  moqtrun_sub_stop(hub, t, s, moqtrun_done_reset_code(status));
  moqtrun_sub_names_forget(p, rid);
  if (!moqtrun_fill_held_for(hub, p->wt, rid)) {
    moqtrun_done_emit(p, q, status, count);
    return;
  }
  q->done_pending = 1;
  q->done_status  = status;
  q->done_count   = count;
}

/* 1 iff q owes a deferred PUBLISH_DONE and f was its subscription's
 * last fill still waiting for a stream. */
static int moqtrun_done_due(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_fetch* f,
    const wired_moqtrun_req*   q) {
  return q && q->done_pending &&
         !moqtrun_fill_held_for(hub, f->wt, f->owner_rid);
}

/* The request stream carrying f's owning subscription, else 0. */
static wired_moqtrun_req* moqtrun_fill_owner_req(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f) {
  wired_moqtrun_peer* p = moqtrun_find_by_wt(hub, f->wt);
  return p ? moqtrun_sub_req(hub, p, f->owner_rid) : 0;
}

/* A fill's stream was granted: the PUBLISH_DONE deferred while it was
 * held goes out once no held fill of its subscription remains. */
static void moqtrun_fill_opened(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f) {
  if (!f->is_fill) return;
  wired_moqtrun_req* q = moqtrun_fill_owner_req(hub, f);
  if (!moqtrun_done_due(hub, f, q)) return;
  moqtrun_done_emit(
      moqtrun_find_by_wt(hub, f->wt), q, q->done_status, q->done_count);
  q->done_pending = 0;
}

/* PUBLISH_DONE status to sub slot si of t, when it is held on a request
 * stream. */
static void moqtrun_sub_done_slot(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz si, u64 status) {
  wired_moqtrun_sub*  s = &t->subs[si];
  wired_moqtrun_peer* p = &hub->peers[s->session_idx];
  wired_moqtrun_req* q = s->active ? moqtrun_sub_req(hub, p, s->request_id) : 0;
  if (q) moqtrun_sub_done(hub, p, q, t, s, status);
}

static u64 moqtrun_pubdone_status(const wired_moqtrun_track* t);

static void moqtrun_track_ended(wired_moqt_hub* hub, wired_moqtrun_track* t) {
  for (usz si = 0; si < WIRED_MOQTRUN_MAX_SUBS; si++)
    moqtrun_sub_done_slot(hub, t, si, moqtrun_pubdone_status(t));
}

/* A publisher's session is ending: every subscription to its tracks ends
 * with TRACK_ENDED (10.11). */
static void moqtrun_peer_tracks_ended(
    wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    if (p->tracks[t].in_use) moqtrun_track_ended(hub, &p->tracks[t]);
}

/* ============ publisher's PUBLISH_DONE relayed (draft 10.11) ============
 * draft-ietf-moq-transport-18/19 10.11, draft-22 9.9. The publisher's
 * PUBLISH_DONE ends its PUBLISH; each subscriber of the track gets its own
 * PUBLISH_DONE: the publisher's Status Code, spelled for the subscriber's
 * draft (moqtrun_done_emit), and as Stream Count the streams the HUB
 * opened toward that subscriber (wired_moqtrun_sub.stream_count) -- the
 * number it can count. The hub is itself a sender bound by "MUST NOT send
 * PUBLISH_DONE until it has closed all streams it will ever open", and
 * the publisher's message may arrive before its late-opening streams, so
 * it waits until the hub saw as many upstream streams as the publisher
 * counted and none is still being relayed; WIRED_MOQTRUN_PUBDONE_WAIT_MS
 * bounds the wait. Then the track is retired and the hub's side of the
 * PUBLISH stream ends (3.3.2). A session close or stream reset meanwhile
 * sends it at once (moqtrun_track_ended, moqtrun_pubdone_flush). */

/* The status a track's subscribers get when it ends now: the publisher's
 * own PUBLISH_DONE status when one is waiting, else TRACK_ENDED. */
static u64 moqtrun_pubdone_status(const wired_moqtrun_track* t) {
  return t->pubdone_pending ? t->pubdone_status : MOQCTL_DONE_TRACK_ENDED;
}

/* p's track claimed by its PUBLISH of Request ID rid, else 0. */
static wired_moqtrun_track* moqtrun_pubdone_track_of(
    wired_moqtrun_peer* p, u64 rid) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    if (moqtrun_track_is_req(&p->tracks[t], rid)) return &p->tracks[t];
  return 0;
}

static int moqtrun_pubdone_relaying(const wired_moqtrun_track* t) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++)
    if (t->relays[r].in_use) return 1;
  return 0;
}

/* Every stream the publisher counted reached the hub and was relayed to
 * its end. */
static int moqtrun_pubdone_caught_up(const wired_moqtrun_track* t) {
  return t->up_streams >= t->pubdone_streams && !moqtrun_pubdone_relaying(t);
}

static int moqtrun_pubdone_armed(const wired_moqtrun_track* t) {
  return t->in_use && t->pubdone_pending;
}

static int moqtrun_pubdone_ready(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  return moqtrun_pubdone_armed(t) &&
         (moqtrun_pubdone_caught_up(t) ||
          hub->live.last_now_ms >= t->pubdone_deadline);
}

static int moqtrun_pubdone_req_is(
    const wired_moqtrun_req* q, const wired_moqtrun_peer* p, u64 rid) {
  return moqtrun_req_owned(q, p->wt) && q->kind == MOQCTL_T_PUBLISH &&
         q->request_id == rid;
}

/* p's PUBLISH rid is complete: the hub's side ends once flushed. */
static void moqtrun_pubdone_req_end(
    wired_moqt_hub* hub, const wired_moqtrun_peer* p, u64 rid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    if (moqtrun_pubdone_req_is(&hub->reqs[i], p, rid)) hub->reqs[i].live = 0;
}

/* PUBLISH_DONE to every subscriber of p's track t (streams still open
 * reset first, moqtrun_sub_done), then t is retired. */
static void moqtrun_pubdone_finish(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_track* t) {
  moqtrun_track_ended(hub, t);
  moqtrun_pubdone_req_end(hub, p, t->request_id);
  t->pubdone_pending = 0;
  moqtrun_track_retire(hub, t);
}

/* 1 when t's waiting PUBLISH_DONE went out. */
static int moqtrun_pubdone_try(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_track* t) {
  if (!moqtrun_pubdone_ready(hub, t)) return 0;
  moqtrun_pubdone_finish(hub, p, t);
  return 1;
}

static int moqtrun_pubdone_peer(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  int n = 0;
  if (!p->in_use) return 0;
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    n += moqtrun_pubdone_try(hub, p, &p->tracks[t]);
  return n;
}

/* Sends every waiting PUBLISH_DONE now due; the request streams are
 * settled only when one went out. */
static void moqtrun_pubdone_sweep(wired_moqt_hub* hub) {
  int n = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    n += moqtrun_pubdone_peer(hub, &hub->peers[i]);
  if (n) moqtrun_reqs_tick(hub);
}

/* p's PUBLISH rid is cancelled: a PUBLISH_DONE still waiting goes out
 * now. */
static void moqtrun_pubdone_flush(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 rid) {
  wired_moqtrun_track* t = moqtrun_pubdone_track_of(p, rid);
  if (t && t->pubdone_pending) moqtrun_pubdone_finish(hub, p, t);
}

/* The track of the PUBLISH whose stream p is handling, else 0. */
static wired_moqtrun_track* moqtrun_pubdone_req_track(wired_moqtrun_peer* p) {
  return p->req ? moqtrun_pubdone_track_of(p, p->req->request_id) : 0;
}

/* The publisher's PUBLISH_DONE on its PUBLISH stream (the request route
 * admits it there only): arm the wait, and send at once when nothing is
 * outstanding. On the control stream it names no PUBLISH: ignored. */
static void moqtrun_dispatch_pub_done(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  usz                  off = 0;
  moqctl_publish_done  d;
  wired_moqtrun_track* t = moqtrun_pubdone_req_track(p);
  (void)peer_idx;
  if (!t || moqctl_publish_done_take(body, &off, &d) != MOQCTL_OK) return;
  t->pubdone_pending  = 1;
  t->pubdone_status   = d.status_code;
  t->pubdone_streams  = d.stream_count;
  t->pubdone_deadline = hub->live.last_now_ms + WIRED_MOQTRUN_PUBDONE_WAIT_MS;
  moqtrun_pubdone_try(hub, p, t);
}

/* ===================== drain (draft 3.6, 10.4) ===================== */

static int moqtrun_encode_goaway(wired_mspan buf, usz* off, const void* m) {
  return moqctl_goaway_encode(buf, off, m);
}

static int moqtrun_encode_goaway18(wired_mspan buf, usz* off, const void* m) {
  return moqctl_goaway18_encode(buf, off, m);
}

/* draft-18 SS10.4: a control-stream GOAWAY ends with a Request ID. */
static moqtrun_body_encode_fn moqtrun_goaway_encoder(int ver) {
  return (moqver_caps(ver) & MOQVER_CAP_GOAWAY_REQID) ? moqtrun_encode_goaway18
                                                      : moqtrun_encode_goaway;
}

/* A session still owed a GOAWAY. */
static int moqtrun_goaway_due(const wired_moqtrun_peer* p) {
  return p->in_use && !p->sess.goaway_sent && !p->closing;
}

/* timeout_ms after the last tick; none for 0. */
static u64 moqtrun_goaway_deadline(const wired_moqt_hub* hub, u64 timeout_ms) {
  return timeout_ms ? hub->live.last_now_ms + timeout_ms : (u64)-1;
}

/* GOAWAY g in p's draft on p's control stream (10.4), noted in its
 * session state. draft-18's Request ID is the smallest one p has not
 * sent yet: the hub handles each request as it arrives. */
static void moqtrun_goaway_one(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, moqctl_goaway g, u64 deadline) {
  u8 msg[WIRED_MOQTRUN_GOAWAY_URI_MAX + 32];
  g.request_id = p->peer_rid_next;
  usz n        = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_GOAWAY,
      moqtrun_goaway_encoder(p->ver), &g);
  moqtrun_queue_reply(p, wired_span_of(msg, n));
  moqtrun_flush_replies(&hub->io, p);
  moqsess_step(&p->sess, MOQSESS_EV_SEND_GOAWAY);
  p->goaway_deadline = deadline;
}

/* p is owed a GOAWAY and is s, or s is 0 (every session). */
static int moqtrun_goaway_target(
    const wired_moqtrun_peer* p, const wired_wt_session* s) {
  return moqtrun_goaway_due(p) && (!s || p->wt == s);
}

/* Sends g to p if it is a target; 1 when sent. */
static int moqtrun_goaway_try(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    const wired_wt_session* s,
    moqctl_goaway           g,
    u64                     deadline) {
  if (!moqtrun_goaway_target(p, s)) return 0;
  moqtrun_goaway_one(hub, p, g, deadline);
  return 1;
}

/* Sends GOAWAY to s, or to every session when s is 0; the count sent. */
static int moqtrun_goaway_send(
    wired_moqt_hub* hub, wired_wt_session* s, wired_span uri, u64 timeout_ms) {
  moqctl_goaway g        = {uri, timeout_ms, 0};
  u64           deadline = moqtrun_goaway_deadline(hub, timeout_ms);
  int           sent     = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    sent += moqtrun_goaway_try(hub, &hub->peers[i], s, g, deadline);
  return sent;
}

/* PUBLISH_DONE status to each subscription peer index idx holds on t. */
static void moqtrun_track_done_peer(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz idx, u64 status) {
  for (usz si = 0; si < WIRED_MOQTRUN_MAX_SUBS; si++)
    if (moqtrun_sub_is_peer(&t->subs[si], idx))
      moqtrun_sub_done_slot(hub, t, si, status);
}

/* Subscription slots of t held by peer index idx. */
static int moqtrun_subs_held(const wired_moqtrun_track* t, usz idx) {
  for (usz si = 0; si < WIRED_MOQTRUN_MAX_SUBS; si++)
    if (moqtrun_sub_is_peer(&t->subs[si], idx)) return 1;
  return 0;
}

static int moqtrun_track_held(const wired_moqtrun_track* t, usz idx) {
  return t->in_use && moqtrun_subs_held(t, idx);
}

static int moqtrun_peer_tracks_held(const wired_moqtrun_peer* q, usz idx) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    if (moqtrun_track_held(&q->tracks[t], idx)) return 1;
  return 0;
}

static int moqtrun_peer_held(const wired_moqtrun_peer* q, usz idx) {
  return q->in_use && moqtrun_peer_tracks_held(q, idx);
}

static int moqtrun_own_held(const wired_moqt_hub* hub, usz idx) {
  return moqtrun_track_held(&hub->blob_track, idx) ||
         moqtrun_track_held(&hub->live.track, idx);
}

/* Peer index idx still holds a subscription on any track. */
static int moqtrun_hub_held(const wired_moqt_hub* hub, usz idx) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (moqtrun_peer_held(&hub->peers[i], idx)) return 1;
  return moqtrun_own_held(hub, idx);
}

static int moqtrun_peer_publishes(const wired_moqtrun_peer* p) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    if (p->tracks[t].in_use) return 1;
  return 0;
}

/* Nothing of p's is open any more: no request stream, no track it
 * publishes, no subscription it holds. */
static int moqtrun_peer_quiet(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  return moqtrun_req_count(hub, p->wt) == 0 && !moqtrun_peer_publishes(p) &&
         !moqtrun_hub_held(hub, (usz)(p - hub->peers));
}

/* draft-ietf-moq-transport-19 10.4: GOAWAY_TIMEOUT only while requests
 * are still open, NO_ERROR (3.5) once nothing is left. */
static u32 moqtrun_drain_close_code(
    wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  return moqtrun_peer_quiet(hub, p) ? WIRED_MOQTRUN_CLOSE_NO_ERROR
                                    : WIRED_MOQTRUN_CLOSE_GOAWAY_TIMEOUT;
}

/* p flushed PUBLISH_DONE and is past the real-time grace that follows:
 * only then may the close happen, so a loaded peer gets WIRED_MOQTRUN_
 * GOAWAY_GRACE_MS of wall-clock time -- not merely the next tick,
 * whenever that lands -- to read the flush before the session is gone. */
static int moqtrun_drain_closeable(const wired_moqtrun_peer* p, u64 now_ms) {
  return p->goaway_flushed_at &&
         now_ms > p->goaway_flushed_at + WIRED_MOQTRUN_GOAWAY_GRACE_MS;
}

/* The flush step of moqtrun_drain_expire: PUBLISH_DONE GOING_AWAY to
 * every subscription p holds, its queued answers sent (the tick's
 * moqtrun_reqs_tick then FINs those streams), and the flush's own
 * timestamp marked for moqtrun_drain_closeable to time the close from. */
static void moqtrun_drain_flush(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 now_ms) {
  moqtrun_each_track(
      hub, moqtrun_track_done_peer, (usz)(p - hub->peers),
      MOQCTL_DONE_GOING_AWAY);
  moqtrun_flush_replies(&hub->io, p);
  p->goaway_flushed_at = now_ms ? now_ms : 1; /* 0 means "not yet" */
}

/* Past the GOAWAY Timeout (3.6): moqtrun_drain_flush once, then close
 * only once moqtrun_drain_closeable allows it (moqtrun_drain_close_code)
 * -- never on the very next tick, so a loaded peer gets real wall-clock
 * time to read the flush before the session is gone. */
static void moqtrun_drain_expire(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 now_ms) {
  if (!p->goaway_flushed_at) {
    moqtrun_drain_flush(hub, p, now_ms);
    return;
  }
  if (moqtrun_drain_closeable(p, now_ms))
    moqtrun_peer_close(hub, p, moqtrun_drain_close_code(hub, p));
}

static int moqtrun_drain_due(const wired_moqtrun_peer* p, u64 now_ms) {
  return p->in_use && !p->closing && now_ms >= p->goaway_deadline;
}

/* A control stream whose open was refused is re-opened; after that,
 * replies refused earlier (moqtrun_flush_replies) are retried. */
static void moqtrun_ctl_step(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  if (!p->ctl_opened) {
    moqtrun_ctl_open(hub, p);
    return;
  }
  moqtrun_flush_replies(&hub->io, p);
}

/* Control-stream opens and replies refused earlier are retried on the
 * clock too, not only when the peer sends again: SETUP and GOAWAY must
 * go out even to a silent peer. */
static void moqtrun_ctl_retry(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  if (p->in_use && !p->closing) moqtrun_ctl_step(hub, p);
}

static void moqtrun_drain_tick(wired_moqt_hub* hub, u64 now_ms) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    if (moqtrun_drain_due(&hub->peers[i], now_ms))
      moqtrun_drain_expire(hub, &hub->peers[i], now_ms);
    moqtrun_ctl_retry(hub, &hub->peers[i]);
    moqtrun_hold_replay(hub, &hub->peers[i]);
  }
}

int wired_moqt_goaway(wired_moqt_hub* hub, wired_span new_uri, u64 timeout_ms) {
  if (new_uri.n > WIRED_MOQTRUN_GOAWAY_URI_MAX) return -1;
  return moqtrun_goaway_send(hub, 0, new_uri, timeout_ms);
}

void wired_moqt_on_session_draining(void* app_ctx, wired_wt_session* s) {
  moqtrun_goaway_send(
      (wired_moqt_hub*)app_ctx, s, wired_span_of(0, 0),
      WIRED_MOQTRUN_DRAIN_TIMEOUT_MS);
}
