#include "app/http3/server/srvloop/srvloop.h"

#include "app/http3/server/srvloop/dispatch.h"
#include "app/http3/server/srvloop/recv.h"
#include "app/http3/server/srvloop/respond.h"
#include "transport/conn/loop/connrunner/level.h"
#include "transport/io/udp/udploop/rxloop.h"
#include "transport/packet/frame/frame/ack.h"
#include "transport/packet/frame/frame/dispatch.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/pipeline/framewalk.h"
#include "transport/packet/header/lhdr/lhdr_parse.h"
#include "transport/packet/header/packet/pnum.h"

#define WIRED_SRVLOOP_MAXPKTS \
  8 /* coalesced packets per datagram (RFC 9000 12.2) */

/* Mark every stream reassembly slot free and its accumulator clean (RFC 9000
 * 2.2) — mirrors the old flat req_len/req_fin/req_done reset in
 * wired_srvloop_init, now done for every slot rather than one fixed field
 * set, so a slot used without going through stream_slot_claim (a direct
 * wired_srvloop_dispatch call, as the tests do) still starts from zero. */
static void streams_reset(wired_srvloop* l) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++) {
    l->streams[i].in_use    = 0;
    l->streams[i].stream_id = 0;
    l->streams[i].req_len   = 0;
    l->streams[i].req_fin   = 0;
    l->streams[i].req_done  = 0;
  }
}

/* Mark every WT bidi stream reassembly slot free (draft-ietf-webtrans-http3-15
 * 4.3), mirroring streams_reset above for the separate wt_streams table. */
static void wt_streams_reset(wired_srvloop* l) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++) {
    l->wt_streams[i].in_use    = 0;
    l->wt_streams[i].stream_id = 0;
    l->wt_streams[i].sig_len   = 0;
    l->wt_streams[i].len       = 0;
    l->wt_streams[i].fin       = 0;
    l->wt_streams[i].offered   = 0;
  }
}

/* Mark every WT uni stream reassembly slot free (draft-ietf-webtrans-http3-15
 * 4.3), mirroring wt_streams_reset above for the separate wt_uni_streams
 * table. */
static void wt_uni_streams_reset(wired_srvloop* l) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++) {
    l->wt_uni_streams[i].in_use    = 0;
    l->wt_uni_streams[i].stream_id = 0;
    l->wt_uni_streams[i].type_len  = 0;
    l->wt_uni_streams[i].len       = 0;
    l->wt_uni_streams[i].fin       = 0;
    l->wt_uni_streams[i].offered   = 0;
  }
}

int wired_srvloop_init(wired_srvloop* l, const u8* cli_scid, u8 cli_scid_len) {
  if (cli_scid_len > 20) return 0;
  l->h3.settings_sent = 0;
  l->h3.peer_control  = 0;
  l->h3.peer_settings = 0;
  l->h3.request_seen  = 0;
  l->cli_scid_len     = cli_scid_len;
  for (usz i = 0; i < cli_scid_len; i++) l->cli_scid[i] = cli_scid[i];
  l->tx_pn                      = 0;
  l->hs_tx_pn                   = 0;
  l->app_rx_pn                  = 0;
  l->app_rx_seen                = 0;
  l->hs_rx_pn                   = 0;
  l->hs_rx_seen                 = 0;
  l->hs_done_sent               = 0;
  l->ticket_sent                = 0;
  l->on_request                 = 0;
  l->req_ctx                    = 0;
  l->got_request                = 0;
  l->peer_closed                = 0;
  l->resp_external              = 0;
  l->ack_n                      = 0;
  l->rx_datagram_n              = 0;
  l->we_advertised_max_datagram = 0;
  l->datagram_violation         = 0;
  l->closed_stream_id           = 0;
  l->closed_stream_seen         = 0;
  l->max_data_seen              = 0;
  l->max_data_seen_flag         = 0;
  l->max_stream_data_n          = 0;
  quic_pnspaces_recv_init(&l->ack_recv);
  quic_ackpolicy_init(&l->app_ack_policy);
  quic_ackpolicy_init(&l->hs_ack_policy);
  l->now_ms = 0;
  streams_reset(l);
  wt_streams_reset(l);
  wt_uni_streams_reset(l);
  return 1;
}

void wired_srvloop_set_handler(
    wired_srvloop* l, wired_srvloop_handler cb, void* ctx) {
  l->on_request = cb;
  l->req_ctx    = ctx;
}

/* The largest 1-RTT packet number received so far (0 before any), the baseline
 * for recovering a truncated PN (RFC 9000 A.3). */
static u64 app_largest_pn(const wired_srvloop* l) {
  return l->app_rx_seen ? l->app_rx_pn : 0;
}

/* The opened packet's level and its (still-mutable) bytes, as note_app_rx /
 * note_hs_rx need both together. */
typedef struct {
  int        level;
  quic_mspan pkt;
} srvloop_opened;

/* RFC 9000 13.2.1 / A.3: once a 1-RTT packet is opened, the truncated (1..4
 * byte) packet number is cleartext in the header (header protection removed in
 * place) and byte0's low bits give its length. Recover the full PN against the
 * largest seen so far and record it as the number to ACK / the new baseline. */
static void note_app_rx(
    wired_srvloop* l, wired_server* s, const srvloop_opened* o) {
  const u8* pn;
  usz       pn_len;
  if (o->level != QUIC_LEVEL_ONERTT) return;
  pn             = o->pkt.p + 1u + s->sdrv.iscid_len;
  pn_len         = (o->pkt.p[0] & 0x03u) + 1u;
  l->app_rx_pn   = quic_pnum_decode(pn, pn_len, app_largest_pn(l));
  l->app_rx_seen = 1;
}

/* The largest Handshake packet number received so far (0 before any), the
 * baseline for recovering a truncated PN (RFC 9000 A.3). */
static u64 hs_largest_pn(const wired_srvloop* l) {
  return l->hs_rx_seen ? l->hs_rx_pn : 0;
}

/* RFC 9000 13.2.1: after a Handshake packet is opened (header protection
 * removed in place), re-parse its long header for the packet-number offset and
 * record the recovered PN. The client Finished does not always arrive at PN 0
 * (curl leads with an ACK-only Handshake packet), so a fixed ACK of 0 leaves
 * the Finished unacknowledged and the client PTO-retransmits it for seconds. */
static void note_hs_rx(wired_srvloop* l, const srvloop_opened* o) {
  quic_lhdr h;
  if (o->level != QUIC_LEVEL_HANDSHAKE) return;
  if (!quic_lhdr_parse(quic_span_of(o->pkt.p, o->pkt.n), 0, &h)) return;
  l->hs_rx_pn = quic_pnum_decode(
      o->pkt.p + h.pn_off, quic_lhdr_pn_len(o->pkt.p[0]), hs_largest_pn(l));
  l->hs_rx_seen = 1;
}

/* 1 if slot is claimed and reassembling stream_id. */
static int slot_matches(const wired_srvloop_stream_slot* slot, u64 stream_id) {
  return slot->in_use && slot->stream_id == stream_id;
}

/* RFC 9000 2.2: find the slot already reassembling stream_id.
 * @return the slot index, or -1 if this stream has no slot yet. */
static int stream_slot_find(const wired_srvloop* l, u64 stream_id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++)
    if (slot_matches(&l->streams[i], stream_id)) return (int)i;
  return -1;
}

/* Claim and reset a free slot for stream_id.
 * @return the slot index, or -1 if the table is full. */
static int stream_slot_claim(wired_srvloop* l, u64 stream_id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++) {
    if (l->streams[i].in_use) continue;
    l->streams[i].in_use    = 1;
    l->streams[i].stream_id = stream_id;
    l->streams[i].req_len   = 0;
    l->streams[i].req_fin   = 0;
    l->streams[i].req_done  = 0;
    return (int)i;
  }
  return -1;
}

/* RFC 9000 2.2: the slot reassembling stream_id, allocating one on first
 * sight. streams[0] is always the first (and, in the single-request-stream
 * case, only) slot ever claimed, since stream id 0 is the first request
 * stream a connection sees — so the pre-existing single-stream behavior is
 * exactly "the table's entry for stream id 0". A full table drops the
 * stream's frames (returns -1), same as the old fixed capacity of one.
 * Public (not static): dispatch.c routes each request STREAM frame to its
 * own stream's slot through this. */
int wired_srvloop_slot_for(wired_srvloop* l, u64 stream_id) {
  int i = stream_slot_find(l, stream_id);
  if (i >= 0) return i;
  return stream_slot_claim(l, stream_id);
}

/* RFC 9000 2.2: free the streams[] slot reassembling stream_id once its
 * response is fully answered and acked -- HTTP/3 never reuses a stream id,
 * so without this the table's 4 slots exhaust after 4 sequential requests
 * on distinct streams. A stream_id with no slot is a no-op. */
void wired_srvloop_slot_release(wired_srvloop* l, u64 stream_id) {
  int i = stream_slot_find(l, stream_id);
  if (i < 0) return;
  l->streams[i].in_use    = 0;
  l->streams[i].stream_id = 0;
  l->streams[i].req_len   = 0;
  l->streams[i].req_fin   = 0;
  l->streams[i].req_done  = 0;
}

/* 1 if wt slot is claimed and reassembling stream_id. */
static int wt_slot_matches(
    const wired_srvloop_wt_stream_slot* slot, u64 stream_id) {
  return slot->in_use && slot->stream_id == stream_id;
}

/* draft-ietf-webtrans-http3-15 4.3: find the wt_streams slot already
 * reassembling stream_id.
 * @return the slot index, or -1 if this stream has no slot yet. */
int wired_srvloop_wt_slot_find(const wired_srvloop* l, u64 stream_id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    if (wt_slot_matches(&l->wt_streams[i], stream_id)) return (int)i;
  return -1;
}

/* Claim and reset a free wt_streams slot for stream_id.
 * @return the slot index, or -1 if the table is full. */
int wired_srvloop_wt_slot_claim(wired_srvloop* l, u64 stream_id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++) {
    if (l->wt_streams[i].in_use) continue;
    l->wt_streams[i].in_use        = 1;
    l->wt_streams[i].stream_id     = stream_id;
    l->wt_streams[i].sig_len       = 0;
    l->wt_streams[i].len           = 0;
    l->wt_streams[i].fin           = 0;
    l->wt_streams[i].offered       = 0;
    l->wt_streams[i].delivered_len = 0;
    l->wt_streams[i].fin_delivered = 0;
    return (int)i;
  }
  return -1;
}

/* 1 if wt uni slot is claimed and reassembling stream_id. */
static int wt_uni_slot_matches(
    const wired_srvloop_wt_uni_stream_slot* slot, u64 stream_id) {
  return slot->in_use && slot->stream_id == stream_id;
}

/* draft-ietf-webtrans-http3-15 4.3: find the wt_uni_streams slot already
 * reassembling stream_id.
 * @return the slot index, or -1 if this stream has no slot yet. */
int wired_srvloop_wt_uni_slot_find(const wired_srvloop* l, u64 stream_id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++)
    if (wt_uni_slot_matches(&l->wt_uni_streams[i], stream_id)) return (int)i;
  return -1;
}

/* Claim and reset a free wt_uni_streams slot for stream_id. */
int wired_srvloop_wt_uni_slot_claim(wired_srvloop* l, u64 stream_id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++) {
    if (l->wt_uni_streams[i].in_use) continue;
    l->wt_uni_streams[i].in_use        = 1;
    l->wt_uni_streams[i].stream_id     = stream_id;
    l->wt_uni_streams[i].type_len      = 0;
    l->wt_uni_streams[i].len           = 0;
    l->wt_uni_streams[i].fin           = 0;
    l->wt_uni_streams[i].offered       = 0;
    l->wt_uni_streams[i].delivered_len = 0;
    l->wt_uni_streams[i].fin_delivered = 0;
    return (int)i;
  }
  return -1;
}

/* RFC 9000 19.19: 1 if type is either CONNECTION_CLOSE variant. */
static int srvloop_close_type(u64 type) {
  return type == QUIC_FRAME_CONN_CLOSE_TPT || type == QUIC_FRAME_CONN_CLOSE_APP;
}

/* RFC 9000 10.2.2: 1 if the opened payload carries a CONNECTION_CLOSE frame
 * (either variant, any encryption level — the peer is closing or draining). */
static int srvloop_has_close(quic_span pl) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  quic_framewalk_init(&it, pl.p, pl.n);
  while (quic_framewalk_next(&it, &fr))
    if (srvloop_close_type(fr.type)) return 1;
  return 0;
}

/* Record one ACK range on l's per-step list; overflow is dropped. */
static void srvloop_push_ack(wired_srvloop* l, u64 lo, u64 hi) {
  if (l->ack_n >= sizeof l->ack_lo / sizeof l->ack_lo[0]) return;
  l->ack_lo[l->ack_n] = lo;
  l->ack_hi[l->ack_n] = hi;
  l->ack_n++;
}

/* Decode one ACK frame and record its ranges (RFC 9000 19.3). */
static void srvloop_take_ack(wired_srvloop* l, const u8* buf, usz n) {
  quic_ack_frame f;
  if (quic_ack_decode(buf, n, &f) == 0) return;
  for (usz i = 0; i < f.n_ranges; i++)
    srvloop_push_ack(l, f.ranges[i].lo, f.ranges[i].hi);
}

/* Surface every ACK frame in the opened payload to the caller's per-step
 * list (RFC 9000 19.3) — the caller consumes them to advance its own sent
 * bookkeeping (e.g. a multi-packet response in flight). */
static void srvloop_collect_acks(wired_srvloop* l, quic_span pl) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  quic_framewalk_init(&it, pl.p, pl.n);
  while (quic_framewalk_next(&it, &fr))
    if (quic_frame_classify(fr.type) == QUIC_FK_ACK)
      srvloop_take_ack(l, fr.start, fr.remaining);
}

/* RFC 9000 13.2: 1 if any frame in pl is ack-eliciting (every frame except
 * PADDING/ACK/CONNECTION_CLOSE). */
static int srvloop_payload_ack_eliciting(quic_span pl) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 eliciting = 0;
  quic_framewalk_init(&it, pl.p, pl.n);
  while (quic_framewalk_next(&it, &fr))
    eliciting |= quic_frame_ack_eliciting(quic_frame_classify(fr.type));
  return eliciting;
}

/* RFC 9000 13.2.1/13.2.2: an ack-eliciting packet in this pn space records
 * pn into its receive window (dedup + reordering-tolerant) and raises the
 * pending count that decides whether/when an ACK is owed. A non-eliciting
 * packet (e.g. ACK-only) touches neither -- receiving only ACKs is never
 * itself a reason to ACK. */
static void srvloop_note_ack_owed(
    quic_pnspaces_recv* recv,
    int                 space,
    quic_ackpolicy*     policy,
    quic_span           pl,
    u64                 pn,
    u64                 now_ms) {
  if (!srvloop_payload_ack_eliciting(pl)) return;
  quic_pnspaces_on_recv(recv, space, pn);
  quic_ackpolicy_on_eliciting(policy, now_ms);
}

/* Dispatch this opened payload. Request STREAM frames are routed per frame
 * to their own stream's slot inside wired_srvloop_dispatch (ctx->l != 0
 * selects the routed path); a slot whose request completes is appended to
 * l->done_slots and mirrored into l->req/req_stream_id there. The in
 * scratch/wrap/req fields are unused on the routed path (each completion
 * uses its own slot's buffers), passed empty. */
static void step_dispatch(const wired_srvloop_conn* conn, quic_span payload) {
  wired_srvloop*            l   = conn->l;
  int                       got = 0;
  wired_srvloop_dispatch_in in  = {
      payload, quic_mspan_of(0, 0), quic_mspan_of(0, 0), &got, &l->req};
  wired_srvloop_dispatch_ctx ctx = {conn->s, &l->h3, 0, l};
  wired_srvloop_dispatch(&ctx, &in);
}

/* This opened slice's level determines which pn space (App/Handshake) owns
 * its ack-eliciting bookkeeping (RFC 9000 12.3); Initial is out of this
 * loop's scope (srvboot's own layer). Split out of step_one to keep its
 * own branch count at the CCN gate. */
static void step_note_ack_owed(wired_srvloop* l, quic_span payload, int level) {
  if (level == QUIC_LEVEL_ONERTT)
    srvloop_note_ack_owed(
        &l->ack_recv, QUIC_PNS_APP, &l->app_ack_policy, payload, l->app_rx_pn,
        l->now_ms);
  if (level == QUIC_LEVEL_HANDSHAKE)
    srvloop_note_ack_owed(
        &l->ack_recv, QUIC_PNS_HANDSHAKE, &l->hs_ack_policy, payload,
        l->hs_rx_pn, l->now_ms);
}

/* RFC 9001 5 / 5.1: open one coalesced packet slice and walk its frames. A
 * STREAM frame sets *got_request; CRYPTO is fed to the handshake. A slice that
 * fails to open (wrong level/key) is silently skipped, as the next slice in the
 * datagram may still be ours (RFC 9000 12.2). */
static void step_one(const wired_srvloop_conn* conn, quic_mspan pkt) {
  wired_srvloop*         l = conn->l;
  wired_server*          s = conn->s;
  wired_srvloop_recv_out ro;
  wired_srvloop_recv_in  ri     = {pkt, app_largest_pn(l)};
  int                    opened = wired_srvloop_recv(s, &ri, &ro);
  srvloop_opened         o;
  if (!opened) return;
  o.level = ro.level;
  o.pkt   = pkt;
  l->peer_closed |= srvloop_has_close(ro.payload);
  /* Restricted to 1-RTT: the caller's bookkeeping (wired_sendsess) keys
   * entries by pn in the 1-RTT space only, so an ACK opened at the Initial/
   * Handshake level could otherwise hit an unrelated 1-RTT pn by
   * coincidence. */
  if (ro.level == QUIC_LEVEL_ONERTT) srvloop_collect_acks(l, ro.payload);
  note_app_rx(l, s, &o);
  note_hs_rx(l, &o);
  step_note_ack_owed(l, ro.payload, ro.level);
  step_dispatch(conn, ro.payload);
}

/* RFC 9000 2.2: re-arm every slot that answered a request this step, so the
 * next request on that stream (curl reuses stream 0 across requests)
 * reassembles from a clean buffer rather than re-triggering the finished
 * one. */
static void rearm_reqacc(wired_srvloop* l) {
  for (usz i = 0; i < l->done_n; i++) {
    wired_srvloop_stream_slot* slot = &l->streams[l->done_slots[i]];
    slot->req_len                   = 0;
    slot->req_fin                   = 0;
    slot->req_done                  = 0;
  }
}

/* RFC 9000 12.2: a received datagram may coalesce several QUIC packets (e.g. an
 * Initial/ACK ahead of the Handshake carrying the client Finished). Split it
 * and process every slice before building one reply for the whole datagram. */
int wired_srvloop_step(
    const wired_srvloop_conn* conn, quic_mspan dgram, quic_obuf* out) {
  const u8*    pkts[WIRED_SRVLOOP_MAXPKTS];
  usz          offs[WIRED_SRVLOOP_MAXPKTS], lens[WIRED_SRVLOOP_MAXPKTS], n, i;
  int          answer;
  int          r;
  quic_pktlist plist = {pkts, offs, lens, WIRED_SRVLOOP_MAXPKTS};
  conn->l->ack_n     = 0;
  conn->l->done_n    = 0;
  n = quic_udploop_split(quic_span_of(dgram.p, dgram.n), &plist);
  for (i = 0; i < n; i++)
    step_one(conn, quic_mspan_of(dgram.p + offs[i], lens[i]));
  conn->l->got_request = conn->l->done_n > 0;
  /* takeover: the caller answers the request, the loop only confirms/ACKs */
  answer = conn->l->got_request && !conn->l->resp_external;
  r      = wired_srvloop_produce(conn, answer, out);
  rearm_reqacc(conn->l);
  return r;
}
