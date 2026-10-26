#include "app/http3/server/srvloop/dispatch_impl.h"

static void push_peer_reset(wired_srvloop* l, u64 id, u64 code, int is_stop);
static int  stream_fin_id(u64 type, wired_span frame, u64* stream_id_out);
static int  closed_frame_id(u64 type, wired_span frame, u64* stream_id_out);
static int  max_data_is_new_high(const wired_srvloop* l, u64 candidate);
static int  max_streams_uni_is_new_high(
    const wired_srvloop* l, int uni, u64 max);
static void gather_one_max_streams_uni(wired_srvloop* l, wired_span frame);
static void note_streams_blocked(wired_srvloop* l, u64 type);
static void gather_one_path_challenge(wired_srvloop* l, wired_span frame);

/* RFC 9000 19.4/19.5: queue one peer RESET_STREAM/STOP_SENDING at the tail
 * of l->peer_resets (wired_srvloop's own doc). Past the queue's end only
 * the count grows, so the caller sees the overflow. */
static void push_peer_reset(wired_srvloop* l, u64 id, u64 code, int is_stop) {
  if (l->peer_reset_n < WIRED_SRVLOOP_RESET_Q) {
    l->peer_resets[l->peer_reset_n] = (wired_srvloop_reset){id, code, is_stop};
  }
  l->peer_reset_n++;
  l->peer_reset_count++;
}

/* RFC 9000 19.4/19.5: if the walked frame at `frame` is a RESET_STREAM or
 * STOP_SENDING, queue its (stream_id, error_code, kind) -- every one this
 * step, unlike srvloop_gather_one_stream_close's last-one-wins latch. l has no
 * notion of which stream id it names; the caller (srvrun.c) resolves it. */
void srvloop_gather_one_wt_reset(wired_srvloop* l, u64 type, wired_span frame) {
  reset_stream_frame rs;
  stop_sending_frame ss;
  if (srvloop_wt_reset_frame(type, frame, &rs)) {
    push_peer_reset(l, rs.stream_id, rs.error_code, 0);
    srvloop_crit_note_close(l, rs.stream_id); /* RFC 9114 6.2.1 */
  }
  if (srvloop_wt_stop_frame(type, frame, &ss)) {
    push_peer_reset(l, ss.stream_id, ss.error_code, 1);
  }
}

/* RFC 9000 19.8: 1 if frame is a client bidi STREAM frame with FIN set,
 * *stream_id_out set to its id — a client-initiated bidi stream (e.g. a
 * WebTransport CONNECT stream, draft-ietf-webtrans-http3-15 SS4.4) ending its
 * client-to-server half. Reuses srvloop_client_bidi_stream_of's own id-space
 * check rather than srvloop_is_request_stream directly, so a stream already
 * claimed by wt_streams[] (checked elsewhere, not here) is not excluded:
 * closing is tracked independent of which path is reassembling the stream's
 * bytes. */
static int stream_fin_id(u64 type, wired_span frame, u64* stream_id_out) {
  stream_frame sf;
  if (!srvloop_client_bidi_stream_of(type, frame, &sf) || !sf.fin) {
    return 0;
  }
  *stream_id_out = sf.stream_id;
  return 1;
}

/* RFC 9000 19.4/19.8: the stream id `frame` (of `type`) closes -- the peer
 * ending its own half with RESET_STREAM or FIN; 0 otherwise. STOP_SENDING
 * is not one: it asks this server to reset its half
 * (srvloop_gather_one_wt_reset queues it, srvrun answers RFC 9000 3.5). Split
 * from srvloop_gather_one_stream_close to keep its own branch count at the CCN
 * gate. */
static int closed_frame_id(u64 type, wired_span frame, u64* stream_id_out) {
  if (srvloop_reset_stream_id(type, frame, stream_id_out)) {
    return 1;
  }
  return stream_fin_id(type, frame, stream_id_out);
}

/* RFC 9000 19.4/19.8: if the walked frame at `frame` closes a stream
 * (closed_frame_id), latch its id into l->closed_stream_id — a peer ending
 * its side of a bidi stream (e.g. the CONNECT stream of a WebTransport
 * session, draft-ietf-webtrans-http3-15 SS4.4) independent of the rest of the
 * connection. l has no notion of what stream_id belongs to; the caller
 * driving the loop (srvrun.c) decides what a closed id means. Only the last
 * one seen this step survives if more than one arrives (mirrors got_request's
 * own "last one wins" mirroring), which is enough for the single-CONNECT-
 * stream-per-connection shape this SDK serves. */
void srvloop_gather_one_stream_close(
    wired_srvloop* l, u64 type, wired_span frame) {
  u64 stream_id;
  if (!closed_frame_id(type, frame, &stream_id)) {
    return;
  }
  l->closed_stream_id   = stream_id;
  l->closed_stream_seen = 1;
}

/* 1 if kind is one of the close-shaped frame kinds srvloop_gather_stream_closes
 * scans for (RESET_STREAM/STOP_SENDING/any STREAM, the latter since a
 * FIN-bearing one is only distinguishable after decoding). Split out to keep
 * srvloop_gather_stream_closes' own branch count at the CCN gate. */
int srvloop_is_close_shaped(frame_kind kind, u64 type) {
  return kind == FK_RESET_STREAM || kind == FK_STOP_SENDING ||
         srvloop_is_stream(type);
}

/* 1 if candidate should replace l->max_data_seen: either nothing latched
 * yet this step, or candidate is the higher of the two seen so far -- split
 * out so srvloop_gather_one_max_data's own CCN stays at the gate (a compound
 * `||` counts as +1 on top of its enclosing if). */
static int max_data_is_new_high(const wired_srvloop* l, u64 candidate) {
  return !l->max_data_seen_flag || candidate > l->max_data_seen;
}

/* RFC 9000 19.9: latch the highest MAX_DATA value seen in this payload --
 * only ever raised by the caller (srvrun.c), never applied here, since RFC
 * 9000 4.1 forbids a send credit from ever decreasing and this loop has no
 * notion of the running credit to compare against. Caller
 * (srvloop_gather_max_data) has already confirmed frame's kind, so this only
 * decodes. */
void srvloop_gather_one_max_data(wired_srvloop* l, wired_span frame) {
  data_frame f;
  if (max_data_decode(frame.p, frame.n, &f) == 0) {
    return;
  }
  if (max_data_is_new_high(l, f.value)) {
    l->max_data_seen = f.value;
  }
  l->max_data_seen_flag = 1;
}

/* RFC 9000 19.11: latch one MAX_STREAMS(uni) frame's value as a running
 * high-water mark (a lower/equal value never lowers it -- limits only ever
 * grow, mirroring max_data_is_new_high). Bidi MAX_STREAMS is ignored here:
 * this server opens no bidi streams the peer's bidi limit would gate except
 * the per-session WT control replies, whose ids the client itself opened. */
/* 1 iff a decoded MAX_STREAMS frame raises the step's uni high-water mark:
 * uni direction only, and only an actual raise (limits never decrease). */
static int max_streams_uni_is_new_high(
    const wired_srvloop* l, int uni, u64 max) {
  return uni && max > l->max_streams_uni_seen;
}

static void gather_one_max_streams_uni(wired_srvloop* l, wired_span frame) {
  int uni;
  u64 max;
  if (!maxstreams_parse(frame, &uni, &max)) {
    return;
  }
  if (!max_streams_uni_is_new_high(l, uni, max)) {
    return;
  }
  l->max_streams_uni_seen      = max;
  l->max_streams_uni_seen_flag = 1;
}

/* RFC 9000 19.11: scan this payload for MAX_STREAMS frames, mirroring
 * srvloop_gather_max_data's shape. Returns 1 if any was seen. */
int srvloop_gather_max_streams_uni(
    wired_srvloop* l, const u8* payload, usz len) {
  framewalk      it;
  framewalk_item fr;
  int            seen = 0;
  framewalk_init(&it, payload, len);
  while (framewalk_next(&it, &fr)) {
    if (frame_classify(fr.type) != FK_MAX_STREAMS) {
      continue;
    }
    seen = 1;
    gather_one_max_streams_uni(l, wired_span_of(fr.start, fr.remaining));
  }
  return seen;
}

/* RFC 9000 19.14: latch which STREAMS_BLOCKED direction was seen -- the two
 * directions carry independent limits, so each gets its own flag. */
static void note_streams_blocked(wired_srvloop* l, u64 type) {
  if (type == FRAME_STREAMS_BLOCKED_BIDI) {
    l->streams_blocked_seen_flag = 1;
  }
  if (type == FRAME_STREAMS_BLOCKED_UNI) {
    l->streams_blocked_uni_seen_flag = 1;
  }
}

/* RFC 9000 19.14: scan this payload for a STREAMS_BLOCKED frame (either
 * direction), mirroring srvloop_gather_max_data's shape. Only the frame's
 * presence matters (srvrun.c computes the re-grant from its own slot state, not
 * the peer's claimed limit -- see streams_blocked_seen_flag's doc), so this
 * just sets the direction's flag rather than decoding a value. Returns 1 if one
 * was seen. */
int srvloop_gather_streams_blocked(
    wired_srvloop* l, const u8* payload, usz len) {
  framewalk      it;
  framewalk_item fr;
  int            seen = 0;
  framewalk_init(&it, payload, len);
  while (framewalk_next(&it, &fr)) {
    if (frame_classify(fr.type) != FK_STREAMS_BLOCKED) {
      continue;
    }
    seen = 1;
    note_streams_blocked(l, fr.type);
  }
  return seen;
}

/* Decode one PATH_RESPONSE frame into l's latch, mirroring
 * srvloop_gather_one_max_data's split (loop body pulled out to keep the
 * scanning loop's own CCN at the gate). A malformed/truncated frame is silently
 * skipped, same policy as srvloop_gather_one_max_data's decode failure. */
/* RFC 9000 8.2.2/19.17: latch the peer's PATH_CHALLENGE data so the owning
 * runner can answer each one; past WIRED_SRVLOOP_PATH_RX they are dropped. */
static void gather_one_path_challenge(wired_srvloop* l, wired_span frame) {
  usz n = l->path_challenge_rx_n;
  if (n >= WIRED_SRVLOOP_PATH_RX) {
    return;
  }
  if (path_decode(
          frame.p, frame.n, FRAME_PATH_CHALLENGE,
          l->path_challenge_rx_data[n])) {
    l->path_challenge_rx_n = n + 1;
  }
}

int srvloop_gather_path_challenge(
    wired_srvloop* l, const u8* payload, usz len) {
  framewalk      it;
  framewalk_item fr;
  int            seen = 0;
  framewalk_init(&it, payload, len);
  while (framewalk_next(&it, &fr)) {
    if (frame_classify(fr.type) != FK_PATH_CHALLENGE) {
      continue;
    }
    seen = 1;
    gather_one_path_challenge(l, wired_span_of(fr.start, fr.remaining));
  }
  return seen;
}
