#include "app/http3/server/srvloop/dispatch_impl.h"

static void gather_one_path_response(wired_srvloop* l, wired_span frame);
static int  ncid_well_formed(usz n, const ncid_frame* f);
static void gather_one_ncid(wired_srvloop* l, wired_span frame);
static int  max_stream_data_slot_for(const wired_srvloop* l, u64 stream_id);
static int  max_stream_data_slot(wired_srvloop* l, u64 stream_id);
static void gather_one_max_stream_data(wired_srvloop* l, wired_span frame);

static void gather_one_path_response(wired_srvloop* l, wired_span frame) {
  if (!path_decode(
          frame.p, frame.n, FRAME_PATH_RESPONSE, l->path_response_data))
    return;
  l->path_response_seen_flag = 1;
}

/* RFC 9000 8.2.2/19.18: scan this payload for a PATH_RESPONSE frame,
 * mirroring srvloop_gather_max_data's shape (latch presence + one fixed-size
 * value, no running-high-water-mark comparison needed). A payload carrying more
 * than one PATH_RESPONSE this step is not expected in practice (the peer
 * answers each challenge in its own packet), so only the
 * last one seen is kept -- exactly srvloop_gather_one_max_data's own
 * last-in-step-among-several convention for a single-slot latch. */
int srvloop_gather_path_response(wired_srvloop* l, const u8* payload, usz len) {
  framewalk      it;
  framewalk_item fr;
  int            seen = 0;
  framewalk_init(&it, payload, len);
  while (framewalk_next(&it, &fr)) {
    if (frame_classify(fr.type) != FK_PATH_RESPONSE) continue;
    seen = 1;
    gather_one_path_response(l, wired_span_of(fr.start, fr.remaining));
  }
  return seen;
}

static int ncid_well_formed(usz n, const ncid_frame* f) {
  return n && ncid_check(f->seq, f->retire_prior_to, f->cid_len);
}

/* RFC 9000 19.15: keep one well-formed NEW_CONNECTION_ID frame for the
 * owner (one past WIRED_SRVLOOP_NCID_RX is skipped); a malformed one latches
 * ncid_malformed, a FRAME_ENCODING_ERROR. */
static void gather_one_ncid(wired_srvloop* l, wired_span frame) {
  ncid_frame f;
  if (!ncid_well_formed(ncid_decode(frame.p, frame.n, &f), &f)) {
    l->ncid_malformed = 1;
    return;
  }
  if (l->ncid_rx_n < WIRED_SRVLOOP_NCID_RX) l->ncid_rx[l->ncid_rx_n++] = f;
}

int srvloop_gather_ncid(wired_srvloop* l, const u8* payload, usz len) {
  framewalk      it;
  framewalk_item fr;
  int            seen = 0;
  framewalk_init(&it, payload, len);
  while (framewalk_next(&it, &fr)) {
    if (frame_classify(fr.type) != FK_NEW_CONNECTION_ID) continue;
    seen = 1;
    gather_one_ncid(l, wired_span_of(fr.start, fr.remaining));
  }
  return seen;
}

/* RFC 9000 19.9: scan this payload for MAX_DATA frames, mirroring
 * srvloop_gather_stream_closes' shape for a different frame kind. Returns 1 if
 * any was seen. */
int srvloop_gather_max_data(wired_srvloop* l, const u8* payload, usz len) {
  framewalk      it;
  framewalk_item fr;
  int            seen = 0;
  framewalk_init(&it, payload, len);
  while (framewalk_next(&it, &fr)) {
    if (frame_classify(fr.type) != FK_MAX_DATA) continue;
    seen = 1;
    srvloop_gather_one_max_data(l, wired_span_of(fr.start, fr.remaining));
  }
  return seen;
}

/* Index of stream_id's existing slot in l's this-step MAX_STREAM_DATA
 * latch, or -1 if it has none yet. */
static int max_stream_data_slot_for(const wired_srvloop* l, u64 stream_id) {
  for (usz i = 0; i < l->max_stream_data_n; i++)
    if (l->max_stream_data_stream_id[i] == stream_id) return (int)i;
  return -1;
}

/* RFC 9000 19.10: latch (stream_id, value) into its own slot -- a repeat
 * stream_id this step overwrites its existing slot (only the newest value
 * for a given stream matters); a new one takes the next free slot, silently
 * dropped if every slot is already used (WIRED_SRVLOOP_MAX_STREAMS already
 * bounds how many distinct request streams this connection reassembles at
 * once, so more distinct MAX_STREAM_DATA targets than that in one step
 * cannot happen). The caller (srvrun.c) resolves which resp[] slot each
 * stream_id belongs to and raises that slot's own running credit, never
 * lowering it (RFC 9000 4.1). */
/* stream_id's slot: its existing one (max_stream_data_slot_for), else a
 * freshly claimed one, else -1 once every slot is already used. */
static int max_stream_data_slot(wired_srvloop* l, u64 stream_id) {
  int i = max_stream_data_slot_for(l, stream_id);
  if (i >= 0) return i;
  if (l->max_stream_data_n >= WIRED_SRVLOOP_MAX_STREAMS) return -1;
  i                               = (int)l->max_stream_data_n++;
  l->max_stream_data_stream_id[i] = stream_id;
  return i;
}

static void gather_one_max_stream_data(wired_srvloop* l, wired_span frame) {
  stream_data_frame f;
  int               i;
  if (max_stream_data_decode(frame.p, frame.n, &f) == 0) return;
  i = max_stream_data_slot(l, f.stream_id);
  if (i >= 0) l->max_stream_data_value[i] = f.value;
}

/* RFC 9000 19.10: scan this payload for MAX_STREAM_DATA frames. Returns 1 if
 * any was seen. */
int srvloop_gather_max_stream_data(
    wired_srvloop* l, const u8* payload, usz len) {
  framewalk      it;
  framewalk_item fr;
  int            seen = 0;
  framewalk_init(&it, payload, len);
  while (framewalk_next(&it, &fr)) {
    if (frame_classify(fr.type) != FK_MAX_STREAM_DATA) continue;
    seen = 1;
    gather_one_max_stream_data(l, wired_span_of(fr.start, fr.remaining));
  }
  return seen;
}

/* RFC 9000 19.4/19.5/19.8: scan this payload for RESET_STREAM/STOP_SENDING/
 * FIN-bearing STREAM frames, mirroring srvloop_gather_rx_datagrams' shape for a
 * different frame kind set. Returns 1 if any was seen this payload (whether
 * or not it was the last one latched); this deliberately does NOT gate
 * dispatch_non_request's handshake-feed fallback the way
 * srvloop_gather_request/ srvloop_gather_wt_stream/srvloop_gather_rx_datagrams
 * do, since a FIN-bearing STREAM frame is already a STREAM frame those paths
 * (or srvloop_has_stream's own check) already account for. */
int srvloop_gather_stream_closes(wired_srvloop* l, const u8* payload, usz len) {
  framewalk      it;
  framewalk_item fr;
  int            seen = 0;
  framewalk_init(&it, payload, len);
  while (framewalk_next(&it, &fr)) {
    if (srvloop_is_close_shaped(frame_classify(fr.type), fr.type)) seen = 1;
    srvloop_gather_one_stream_close(
        l, fr.type, wired_span_of(fr.start, fr.remaining));
    srvloop_gather_one_wt_reset(
        l, fr.type, wired_span_of(fr.start, fr.remaining));
  }
  return seen;
}
