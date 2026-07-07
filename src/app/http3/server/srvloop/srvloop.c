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
  l->tx_pn         = 0;
  l->hs_tx_pn      = 0;
  l->app_rx_pn     = 0;
  l->app_rx_seen   = 0;
  l->hs_rx_pn      = 0;
  l->hs_rx_seen    = 0;
  l->hs_done_sent  = 0;
  l->ticket_sent   = 0;
  l->on_request    = 0;
  l->req_ctx       = 0;
  l->got_request   = 0;
  l->peer_closed   = 0;
  l->resp_external = 0;
  l->ack_n         = 0;
  l->rx_datagram_n = 0;
  l->we_advertised_max_datagram = 0;
  l->datagram_violation         = 0;
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
 * stream's frames (returns -1), same as the old fixed capacity of one. */
static int stream_slot_for(wired_srvloop* l, u64 stream_id) {
  int i = stream_slot_find(l, stream_id);
  if (i >= 0) return i;
  return stream_slot_claim(l, stream_id);
}

/* 1 if wt slot is claimed and reassembling stream_id. */
static int wt_slot_matches(const wired_srvloop_wt_stream_slot* slot, u64 stream_id) {
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
    l->wt_streams[i].in_use    = 1;
    l->wt_streams[i].stream_id = stream_id;
    l->wt_streams[i].sig_len   = 0;
    l->wt_streams[i].len       = 0;
    l->wt_streams[i].fin       = 0;
    l->wt_streams[i].offered   = 0;
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
    l->wt_uni_streams[i].in_use    = 1;
    l->wt_uni_streams[i].stream_id = stream_id;
    l->wt_uni_streams[i].type_len  = 0;
    l->wt_uni_streams[i].len       = 0;
    l->wt_uni_streams[i].fin       = 0;
    l->wt_uni_streams[i].offered   = 0;
    return (int)i;
  }
  return -1;
}

/* RFC 9000 2.2: view one stream slot's cross-datagram request accumulator. */
static wired_srvloop_reqacc slot_reqacc(wired_srvloop_stream_slot* slot) {
  wired_srvloop_reqacc acc;
  acc.buf  = slot->req_buf;
  acc.cap  = sizeof slot->req_buf;
  acc.len  = &slot->req_len;
  acc.fin  = &slot->req_fin;
  acc.done = &slot->req_done;
  return acc;
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

/* RFC 9000 2.2: the slot this payload's frames dispatch into — its own
 * request stream's slot when a request-stream frame is present, else slot 0
 * as a scratch landing pad for a CRYPTO/handshake payload (which never
 * reaches reassemble_and_drive far enough to touch it; RFC 9000 12.4). A
 * request stream beyond WIRED_SRVLOOP_MAX_STREAMS capacity has no slot
 * (matching the old fixed capacity of one) and its frames are dropped. */
static int step_slot_for(wired_srvloop* l, quic_span payload) {
  u64 stream_id;
  if (!wired_srvloop_payload_stream_id(l, payload, &stream_id)) return 0;
  return stream_slot_for(l, stream_id);
}

/* Landing pad for a payload with no request-stream frame (CRYPTO/handshake):
 * reassemble_and_drive's gather_request never matches a frame on this path, so
 * this slot's buffers are never actually read or written — one static instance
 * avoids re-zeroing ~4.6KB of stack on every non-request packet (every
 * Initial/Handshake step, RFC 9000 12.4). Not connection state: nothing here
 * is meaningful across calls. */
static wired_srvloop_stream_slot g_srvloop_no_slot;

/* Dispatch this opened payload into slot i (or, when i < 0, accept only the
 * non-request/handshake path — a full stream table drops the request-stream
 * frames rather than corrupting an unrelated slot). *got_request/l->req mirror
 * the pre-existing single-stream API surface: when this call newly decodes a
 * request, they are updated to it and slot i is recorded as the one to rearm
 * after the whole datagram is processed. */
static void step_dispatch(
    const wired_srvloop_conn* conn,
    quic_span                 payload,
    int                       slot_i,
    int*                      got_request,
    int*                      done_slot) {
  wired_srvloop*             l = conn->l;
  wired_srvloop_stream_slot* slot =
      slot_i >= 0 ? &l->streams[slot_i] : &g_srvloop_no_slot;
  wired_srvloop_reqacc      acc = slot_reqacc(slot);
  int                       got = 0;
  wired_srvloop_dispatch_in in  = {
      payload, quic_mspan_of(slot->req_scratch, sizeof slot->req_scratch),
      quic_mspan_of(slot->req_wrap, sizeof slot->req_wrap), &got, &slot->req};
  wired_srvloop_dispatch_ctx ctx = {conn->s, &l->h3, &acc, l};
  wired_srvloop_dispatch(&ctx, &in);
  if (!got) return;
  *got_request     = 1;
  *done_slot       = slot_i;
  l->req           = slot->req;
  l->req_stream_id = slot->stream_id;
}

/* RFC 9001 5 / 5.1: open one coalesced packet slice and walk its frames. A
 * STREAM frame sets *got_request; CRYPTO is fed to the handshake. A slice that
 * fails to open (wrong level/key) is silently skipped, as the next slice in the
 * datagram may still be ours (RFC 9000 12.2). */
static void step_one(
    const wired_srvloop_conn* conn,
    quic_mspan                pkt,
    int*                      got_request,
    int*                      done_slot) {
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
  srvloop_collect_acks(l, ro.payload);
  note_app_rx(l, s, &o);
  note_hs_rx(l, &o);
  step_dispatch(
      conn, ro.payload, step_slot_for(l, ro.payload), got_request, done_slot);
}

/* RFC 9000 2.2: re-arm the slot that answered this step's request, so the next
 * request on that stream (curl reuses stream 0 across requests) reassembles
 * from a clean buffer rather than re-triggering the finished one. */
static void rearm_reqacc(wired_srvloop* l, int got_request, int done_slot) {
  wired_srvloop_stream_slot* slot;
  if (!got_request || done_slot < 0) return;
  slot           = &l->streams[done_slot];
  slot->req_len  = 0;
  slot->req_fin  = 0;
  slot->req_done = 0;
}

/* RFC 9000 12.2: a received datagram may coalesce several QUIC packets (e.g. an
 * Initial/ACK ahead of the Handshake carrying the client Finished). Split it
 * and process every slice before building one reply for the whole datagram. */
int wired_srvloop_step(
    const wired_srvloop_conn* conn, quic_mspan dgram, quic_obuf* out) {
  const u8*    pkts[WIRED_SRVLOOP_MAXPKTS];
  usz          offs[WIRED_SRVLOOP_MAXPKTS], lens[WIRED_SRVLOOP_MAXPKTS], n, i;
  int          got_request = 0;
  int          done_slot   = -1;
  int          answer;
  int          r;
  quic_pktlist plist = {pkts, offs, lens, WIRED_SRVLOOP_MAXPKTS};
  conn->l->ack_n     = 0;
  n = quic_udploop_split(quic_span_of(dgram.p, dgram.n), &plist);
  for (i = 0; i < n; i++)
    step_one(
        conn, quic_mspan_of(dgram.p + offs[i], lens[i]), &got_request,
        &done_slot);
  conn->l->got_request = got_request;
  /* takeover: the caller answers the request, the loop only confirms/ACKs */
  answer = got_request && !conn->l->resp_external;
  r      = wired_srvloop_produce(conn, answer, out);
  rearm_reqacc(conn->l, got_request, done_slot);
  return r;
}
