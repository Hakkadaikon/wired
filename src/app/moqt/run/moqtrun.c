#include "app/moqt/run/moqtrun.h"

#include "app/moqt/ctl/moqctl.h"
#include "app/moqt/data/moqdata.h"
#include "app/moqt/vi/moqvi.h"
#include "common/bytes/util/bytes.h"

/* draft-ietf-moq-transport-19 hub relay (M5-6). See moqtrun.h for the
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
 * SETUP, no Setup Options (this subset negotiates nothing on the wire). */
static u64 moqtrun_send_setup(wired_moqt_io* io, wired_wt_session* s) {
  u8                buf[16];
  quic_moqctl_setup setup = {0};
  usz               n     = moqtrun_envelope_put(
      quic_mspan_of(buf, sizeof buf), QUIC_MOQCTL_T_SETUP, moqtrun_encode_setup,
      &setup);
  i64 sid = io->open_bidi_stream(s, quic_span_of(buf, n));
  return sid < 0 ? 0 : (u64)sid;
}

void wired_moqt_on_session(
    void* app_ctx, wired_wt_session* s, quic_span path, quic_span protocol) {
  (void)path;
  (void)protocol;
  wired_moqt_hub*     hub = (wired_moqt_hub*)app_ctx;
  wired_moqtrun_peer* p   = moqtrun_alloc(hub);
  if (!p) return;
  p->in_use          = 1;
  p->wt              = s;
  p->published       = 0;
  p->request_id_next = 1; /* hub is the server: odd, 1-origin (draft SS10.2) */
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) p->subs[i].active = 0;
  quic_moqsess_init(&p->sess);
  p->control_stream_id = moqtrun_send_setup(&hub->io, s);
  quic_moqsess_step(&p->sess, QUIC_MOQSESS_EV_SENT_SETUP);
}

/* ===================== control-message handlers ===================== */

/* draft SS10.2 Message Parameter types this hub refuses to accept/send
 * (T-174/T-175 loss-free-hub timeout defense). */
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

static int moqtrun_encode_request_error(
    quic_mspan buf, usz* off, const void* m) {
  return quic_moqctl_request_error_encode(buf, off, m);
}

static void moqtrun_send_request_error(
    wired_moqt_io* io, wired_wt_session* s, u64 stream_id, u64 code) {
  u8                        buf[64];
  quic_moqctl_request_error e = {0};
  e.error_code                = code;
  usz n                       = moqtrun_envelope_put(
      quic_mspan_of(buf, sizeof buf), QUIC_MOQCTL_T_REQUEST_ERROR,
      moqtrun_encode_request_error, &e);
  io->stream_send(s, stream_id, quic_span_of(buf, n), 0);
}

/* Copies name into p->name (Track Name = participant id), truncated to
 * WIRED_MOQTRUN_MAX_NAME (room ids are short; a real deployment would
 * reject an oversized one instead -- ponytail: no such input in this
 * subset's usage). */
static void moqtrun_record_name(wired_moqtrun_peer* p, quic_span name) {
  usz n = name.n < WIRED_MOQTRUN_MAX_NAME ? name.n : WIRED_MOQTRUN_MAX_NAME;
  quic_memcpy(p->name, name.p, n);
  p->name_len = n;
}

static int moqtrun_encode_request_ok(quic_mspan buf, usz* off, const void* m) {
  return quic_moqctl_request_ok_encode(buf, off, m);
}

/* draft SS10.9 PUBLISH: accept unconditionally (this subset trusts every
 * connected peer to publish its own fixed track) and reply REQUEST_OK. */
static void moqtrun_handle_publish(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, quic_span body) {
  usz                 off = 0;
  quic_moqctl_publish m;
  if (quic_moqctl_publish_take(body, &off, &m) != QUIC_MOQCTL_OK) return;
  p->published = 1;
  moqtrun_record_name(p, m.name.name);
  u8                     buf[16];
  quic_moqctl_request_ok ok = {0};
  usz                    n  = moqtrun_envelope_put(
      quic_mspan_of(buf, sizeof buf), QUIC_MOQCTL_T_REQUEST_OK,
      moqtrun_encode_request_ok, &ok);
  hub->io.stream_send(p->wt, p->control_stream_id, quic_span_of(buf, n), 0);
}

static int moqtrun_peer_is_published(const wired_moqtrun_peer* p) {
  return p->in_use && p->published;
}

static int moqtrun_bytes_eq(const u8* a, const u8* b, usz n) {
  for (usz i = 0; i < n; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

static int moqtrun_name_matches(const wired_moqtrun_peer* p, quic_span name) {
  return p->name_len == name.n && moqtrun_bytes_eq(p->name, name.p, name.n);
}

static int moqtrun_peer_published_as(
    const wired_moqtrun_peer* p, quic_span name) {
  return moqtrun_peer_is_published(p) && moqtrun_name_matches(p, name);
}

/* Finds the peer whose own PUBLISHed Track Name equals the requested
 * SUBSCRIBE's Track Name (M5-6: room membership keys on participant id,
 * namespace is hub-fixed and not compared). */
static wired_moqtrun_peer* moqtrun_find_published(
    wired_moqt_hub* hub, const quic_moqctl_ftn* name) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (moqtrun_peer_published_as(&hub->peers[i], name->name))
      return &hub->peers[i];
  return 0;
}

static wired_moqtrun_sub* moqtrun_sub_slot(wired_moqtrun_peer* pub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (!pub->subs[i].active) return &pub->subs[i];
  return 0;
}

static u64 moqtrun_alias_floor(const wired_moqtrun_peer* pub, usz i) {
  return pub->subs[i].active ? pub->subs[i].track_alias + 1 : 0;
}

static u64 moqtrun_next_alias(const wired_moqtrun_peer* pub) {
  u64 max_seen = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    u64 floor = moqtrun_alias_floor(pub, i);
    if (floor > max_seen) max_seen = floor;
  }
  return max_seen;
}

static int moqtrun_encode_subscribe_ok(
    quic_mspan buf, usz* off, const void* m) {
  return quic_moqctl_subscribe_ok_encode(buf, off, m);
}

/* Records slot (peer_idx, a fresh alias) against pub and replies
 * SUBSCRIBE_OK with that alias. */
static void moqtrun_accept_subscribe(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_peer* pub,
    wired_moqtrun_sub*  slot,
    usz                 peer_idx) {
  slot->session_idx = peer_idx;
  slot->track_alias = moqtrun_next_alias(pub);
  slot->active      = 1;
  u8                       buf[16];
  quic_moqctl_subscribe_ok ok = {0};
  ok.track_alias              = slot->track_alias;
  usz n                       = moqtrun_envelope_put(
      quic_mspan_of(buf, sizeof buf), QUIC_MOQCTL_T_SUBSCRIBE_OK,
      moqtrun_encode_subscribe_ok, &ok);
  hub->io.stream_send(p->wt, p->control_stream_id, quic_span_of(buf, n), 0);
}

/* draft SS10.6 SUBSCRIBE: find the matching published peer and reply
 * SUBSCRIBE_OK with a freshly assigned Track Alias, else DOES_NOT_EXIST
 * (T-145). Caller has already rejected timeout parameters (T-175). */
static void moqtrun_route_subscribe(
    wired_moqt_hub*              hub,
    wired_moqtrun_peer*          p,
    usz                          peer_idx,
    const quic_moqctl_subscribe* m) {
  wired_moqtrun_peer* pub  = moqtrun_find_published(hub, &m->name);
  wired_moqtrun_sub*  slot = pub ? moqtrun_sub_slot(pub) : 0;
  if (!slot) {
    moqtrun_send_request_error(
        &hub->io, p->wt, p->control_stream_id, QUIC_MOQCTL_ERR_DOES_NOT_EXIST);
    return;
  }
  moqtrun_accept_subscribe(hub, p, pub, slot, peer_idx);
}

/* draft SS10.6 SUBSCRIBE: reject non-zero delivery-timeout parameters
 * (T-175), else delegate matching + response to moqtrun_route_subscribe. */
static void moqtrun_handle_subscribe(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, quic_span body) {
  usz                   off = 0;
  quic_moqctl_subscribe m;
  if (quic_moqctl_subscribe_take(body, &off, &m) != QUIC_MOQCTL_OK) return;
  if (moqtrun_has_timeout_param(&m.params)) {
    moqtrun_send_request_error(
        &hub->io, p->wt, p->control_stream_id, QUIC_MOQCTL_ERR_NOT_SUPPORTED);
    return;
  }
  moqtrun_route_subscribe(hub, p, peer_idx, &m);
}

static void moqtrun_handle_not_supported(
    wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  moqtrun_send_request_error(
      &hub->io, p->wt, p->control_stream_id, QUIC_MOQCTL_ERR_NOT_SUPPORTED);
}

/* draft 5.1: a GOAWAY arriving on a request stream (not the control
 * stream) is informational in this subset -- accepted without closing the
 * session (T-173). The 2nd-GOAWAY-on-one-stream violation is a sess-layer
 * concern the caller already routes through quic_moqsess_step; nothing
 * further to do here since this hub sends no GOAWAY of its own on a
 * request stream. */
static void moqtrun_handle_request_goaway(void) {}

typedef void (*moqtrun_ctl_fn)(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, quic_span body);

static void moqtrun_dispatch_publish(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, quic_span body) {
  (void)peer_idx;
  moqtrun_handle_publish(hub, p, body);
}

static void moqtrun_dispatch_subscribe(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, quic_span body) {
  moqtrun_handle_subscribe(hub, p, peer_idx, body);
}

static void moqtrun_dispatch_not_supported(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, quic_span body) {
  (void)peer_idx;
  (void)body;
  moqtrun_handle_not_supported(hub, p);
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
 * fresh request stream gets NOT_SUPPORTED (M5-6 point 8). GOAWAY is not a
 * First type but may legally appear mid-stream (T-173), so it is routed
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
 * to record which session a subscription belongs to. */
static void moqtrun_dispatch_ctl_stream(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, quic_span data) {
  usz off = 0;
  while (off < data.n) {
    u64       type = 0;
    quic_span body = {0, 0};
    int       r    = quic_moqctl_peek_type(data, &off, &type, &body);
    if (r != QUIC_MOQCTL_OK) return;
    moqtrun_ctl_lookup(type)(hub, p, peer_idx, body);
  }
}

/* ===================== data-stream (Object) relay ===================== */

/* Sends wire (a complete SUBGROUP_HEADER+Object stream, unmodified: T-146)
 * to one subscriber, whole, as exactly one fresh uni stream (T-136/T-147),
 * FIN'd once fully queued. srvrun's open_uni_stream never sends FIN
 * itself, so a bare empty stream_send(..., fin=1) closes it (see
 * moqtrun.h's io table doc). */
static void moqtrun_relay_to_one(
    wired_moqt_hub* hub, const wired_moqtrun_sub* sub, quic_span wire) {
  wired_moqtrun_peer* dst = &hub->peers[sub->session_idx];
  if (!dst->in_use) return;
  i64 sid = hub->io.open_uni_stream(dst->wt, wire);
  if (sid < 0) return;
  hub->io.stream_send(dst->wt, (u64)sid, quic_span_of(0, 0), 1);
}

static void moqtrun_relay_object(
    wired_moqt_hub* hub, wired_moqtrun_peer* pub, quic_span wire) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (pub->subs[i].active) moqtrun_relay_to_one(hub, &pub->subs[i], wire);
}

/* Decodes the SUBGROUP_HEADER + the one Object this subset always sends
 * whole in one call (M5-6 point 5: 1 message = 1 Object = 1 Group = 1
 * Subgroup). Returns 1 on a fully decoded Object, 0 otherwise (nothing to
 * relay -- covers INSUFFICIENT/VIOLATION alike, since a hub-internal relay
 * has no peer to report a VIOLATION to at this call site). */
static int moqtrun_decode_one_object(quic_span data, usz* off) {
  quic_moqdata_subhdr hdr;
  if (quic_moqdata_subhdr_take(data, off, &hdr) != QUIC_MOQDATA_OK) return 0;
  quic_moqdata_objseq seq = quic_moqdata_objseq_of(hdr.type);
  quic_moqdata_obj    obj;
  return quic_moqdata_obj_take(data, off, &seq, &obj) == QUIC_MOQDATA_OK;
}

/* draft 3.4/11.4.2: classify a fresh data stream and, for SUBGROUP_HEADER,
 * relay it verbatim once its Object decodes. Padding streams
 * (0x132B3E28, T-149) and any other classification are discarded here:
 * classification-level session closes are the sess layer's job, driven
 * elsewhere from the same decoded quic_moqsess_event. */
static void moqtrun_dispatch_data_stream(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, quic_span data) {
  usz classify_off = 0;
  int kind         = quic_moqdata_classify(data, &classify_off);
  (void)classify_off;
  if (kind != QUIC_MOQDATA_STREAM_SUBGROUP) return;
  /* SUBGROUP_HEADER's Type byte is left unconsumed by classify (moqdata.h
   * doc): quic_moqdata_subhdr_take re-reads it from the stream's start. */
  usz off = 0;
  if (moqtrun_decode_one_object(data, &off)) moqtrun_relay_object(hub, p, data);
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
  moqtrun_dispatch_data_stream(hub, p, data);
}
