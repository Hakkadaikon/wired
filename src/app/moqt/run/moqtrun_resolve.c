#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_track_pub_rid(const wired_moqtrun_track* t, u64 rid);
static int moqtrun_peer_pub_rid(const wired_moqtrun_peer* p, u64 rid);
static int moqtrun_inbound_fetch_routed(
    const wired_moqtrun_peer* p, wired_span data);
static int  moqtrun_fetch_hdr_short(wired_span data, int fin);
static void moqtrun_fetch_stream_refuse(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin);
static void moqtrun_fetch_stream_route(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin);

/* Classifies a FRESH data stream's leading Stream Type varint and, for
 * SUBGROUP_HEADER, decodes the header + every following Object,
 * resolving the header's Track Alias to one of p's (chat/audio) track
 * slots -- else 0 (not a SUBGROUP stream, header decode failure, zero
 * Objects decoded on a one-shot fin delivery, or an unknown Track
 * Alias). */
wired_moqtrun_track* moqtrun_resolve_fresh_stream_track(
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

/* 1 iff rid names the request behind one of p's own tracks: p's PUBLISH,
 * or the hub's own upstream SUBSCRIBE whose SUBSCRIBE_OK claimed it
 * (moqtrun_up_claim) -- the only requests this hub holds upstream. */
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
void moqtrun_stream_stop(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 sid, u32 code) {
  if (hub->io.stream_stop) hub->io.stream_stop(p->wt, sid, code);
}

/* A first delivery ending inside its FETCH_HEADER (Type, then a cut
 * Request ID). */
static int moqtrun_fetch_hdr_short(wired_span data, int fin) {
  usz at  = 0;
  u64 rid = 0;
  return !fin && moqfetch_hdr_take(data, &at, &rid) == MOQCTL_INSUFFICIENT;
}

/* Such a stream is kept (the one early slot) until the next delivery
 * completes its header (moqtrun_early_refetch). 1 when kept. */
int moqtrun_fetch_hdr_keep(
    wired_moqtrun_peer* p, u64 sid, wired_span data, int fin) {
  if (!moqtrun_fetch_hdr_short(data, fin) || !moqtrun_early_free(p, data.n))
    return 0;
  moqtrun_early_put(p, sid, data, fin);
  return 1;
}

/* sid is asked to stop with CANCELLED; a cut header ends the upstream
 * FETCHes it might have answered (moqtrun_upf_torn_unheld). */
static void moqtrun_fetch_stream_refuse(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  moqtrun_stream_stop(hub, p, sid, MOQTRUN_RESET_CANCELLED);
  if (moqtrun_fetch_hdr_short(data, fin)) moqtrun_upf_torn_unheld(hub, p->wt);
}

/* A fetch data stream's whole FETCH_HEADER routes it by Request ID: one
 * of the hub's own upstream FETCHes takes it (moqtrun_upf_bind); one
 * naming the PUBLISH behind a track of this peer is accepted against it
 * (its Objects dropped); any other -- one answering an upstream FETCH
 * already cancelled, say -- is asked to stop with CANCELLED. */
static void moqtrun_fetch_stream_route(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  if (moqtrun_upf_bind(hub, p, sid, data, fin)) return;
  if (!moqtrun_inbound_fetch_routed(p, data))
    moqtrun_fetch_stream_refuse(hub, p, sid, data, fin);
}

/* A fresh uni classifying as a fetch data stream (FETCH_HEADER, 11.4.4).
 * The session never closes over an unroutable fetch stream. 1 when
 * consumed. */
int moqtrun_fresh_fetch_stream(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  usz at = 0;
  if (moqdata_classify(data, &at) != MOQDATA_STREAM_FETCH) return 0;
  if (!moqtrun_fetch_hdr_keep(p, sid, data, fin))
    moqtrun_fetch_stream_route(hub, p, sid, data, fin);
  return 1;
}

/* 1 iff data opens a SUBGROUP stream whose Track Alias names none of p's
 * tracks. */
int moqtrun_early_alias_unknown(wired_moqtrun_peer* p, wired_span data) {
  usz            at = 0, off = 0;
  moqdata_subhdr h;
  if (moqdata_classify(data, &at) != MOQDATA_STREAM_SUBGROUP) return 0;
  if (moqdata_subhdr_take(data, &off, &h) != MOQDATA_OK) return 0;
  return moqtrun_track_by_alias(p, h.track_alias) == 0;
}
