#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_early_room(const wired_moqtrun_peer* p, usz n);
static int moqtrun_early_wanted(
    const wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_span data);
static void moqtrun_early_stash(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin);
static int  moqtrun_early_is(const wired_moqtrun_peer* p, u64 sid);
static void moqtrun_fresh_subgroup_relay(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);

static int moqtrun_early_room(const wired_moqtrun_peer* p, usz n) {
  return p->early_n + n <= WIRED_MOQTRUN_EARLY_BUF;
}

int moqtrun_early_free(const wired_moqtrun_peer* p, usz n) {
  return p->early_n == 0 && moqtrun_early_room(p, n);
}

/* 1 iff a fresh stream no track claims is kept: none is kept yet, it
 * fits, p has an unanswered upstream SUBSCRIBE and the alias is unknown. */
static int moqtrun_early_wanted(
    const wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_span data) {
  return moqtrun_early_free(p, data.n) && moqtrun_up_pending_for(hub, p->wt) &&
         moqtrun_early_alias_unknown(p, data);
}

void moqtrun_early_put(
    wired_moqtrun_peer* p, u64 sid, wired_span data, int fin) {
  bytes_memcpy(p->early + p->early_n, data.p, data.n);
  p->early_n += data.n;
  p->early_sid = sid;
  p->early_fin = fin;
}

static void moqtrun_early_stash(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  if (moqtrun_early_wanted(hub, p, data)) {
    moqtrun_early_put(p, sid, data, fin);
  }
}

static int moqtrun_early_is(const wired_moqtrun_peer* p, u64 sid) {
  return p->early_n != 0 && p->early_sid == sid;
}

/* A later delivery of the kept stream follows it; one that does not fit
 * drops the stream. 1 when sid is the kept stream. */
int moqtrun_early_more(
    wired_moqtrun_peer* p, u64 sid, wired_span data, int fin) {
  if (!moqtrun_early_is(p, sid)) {
    return 0;
  }
  if (moqtrun_early_room(p, data.n)) {
    moqtrun_early_put(p, sid, data, fin);
  } else {
    p->early_n = 0;
  }
  return 1;
}

/* The kept stream was reset: nothing of it is relayed. */
void moqtrun_early_drop(wired_moqtrun_peer* p, u64 sid) {
  if (moqtrun_early_is(p, sid)) {
    p->early_n = 0;
  }
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
  if (!track) {
    moqtrun_early_stash(hub, p, stream_id, data, fin);
    return;
  }
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
void moqtrun_dispatch_fresh_stream(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  if (moqtrun_fresh_fetch_stream(hub, p, stream_id, data, fin)) {
    return;
  }
  moqtrun_fresh_subgroup_relay(hub, p, stream_id, data, fin);
}

/* The kept stream is a fetch data stream whose header was cut: it is
 * classified again with what arrived (moqtrun_fetch_hdr_keep). */
void moqtrun_early_refetch(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  usz at = 0;
  if (moqdata_classify(wired_span_of(p->early, p->early_n), &at) ==
      MOQDATA_STREAM_FETCH) {
    moqtrun_early_replay(hub, p);
  }
}

/* An upstream SUBSCRIBE_OK claimed a track of p: the kept stream replays
 * as fresh -- relayed when its alias is now known, else kept again for a
 * later OK (moqtrun_early_stash copies it onto itself). */
void moqtrun_early_replay(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  usz n = p->early_n;
  if (!n) {
    return;
  }
  p->early_n = 0;
  moqtrun_dispatch_fresh_stream(
      hub, p, p->early_sid, wired_span_of(p->early, n), p->early_fin);
}

/* sid is the hub's own, opened control stream (the legacy bidi the
 * client writes back on; a failed open never aliases a client id). */
int moqtrun_rx_is_own_ctl(const wired_moqtrun_peer* p, u64 sid) {
  return p->ctl_opened && sid == p->control_stream_id;
}

/* draft-19 3.3: control streams stay open for the session's life -- a
 * transport-level end (FIN, RESET_STREAM, STOP_SENDING) of either one
 * closes the session with PROTOCOL_VIOLATION. */
void moqtrun_ctl_gone(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  moqsess_step(&p->sess, MOQSESS_EV_CTRL_CLOSED);
  moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
}
