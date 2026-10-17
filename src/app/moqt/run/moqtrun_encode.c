#include "app/moqt/run/moqtrun_impl.h"

static wired_moqtrun_track* moqtrun_pubdone_req_track(wired_moqtrun_peer* p);
static int moqtrun_encode_goaway(wired_mspan buf, usz* off, const void* m);
static int moqtrun_encode_goaway18(wired_mspan buf, usz* off, const void* m);
static moqtrun_body_encode_fn moqtrun_goaway_encoder(int ver);
static int                    moqtrun_goaway_due(const wired_moqtrun_peer* p);
static u64 moqtrun_goaway_deadline(const wired_moqt_hub* hub, u64 timeout_ms);
static wired_span moqtrun_goaway_uri(
    const wired_moqtrun_peer* p, wired_span uri);
static void moqtrun_goaway_one(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, moqctl_goaway g, u64 deadline);
static int moqtrun_goaway_target(
    const wired_moqtrun_peer* p, const wired_wt_session* s);
static int moqtrun_goaway_try(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    const wired_wt_session* s,
    moqctl_goaway           g,
    u64                     deadline);

/* The track of the PUBLISH whose stream p is handling, else 0. */
static wired_moqtrun_track* moqtrun_pubdone_req_track(wired_moqtrun_peer* p) {
  return p->req ? moqtrun_pubdone_track_of(p, p->req->request_id) : 0;
}

/* The publisher's PUBLISH_DONE body for its track t: arm the wait, and
 * send at once when nothing is outstanding. */
void moqtrun_pubdone_arm(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* t,
    wired_span           body) {
  usz                 off = 0;
  moqctl_publish_done d;
  if (moqctl_publish_done_take(body, &off, &d) != MOQCTL_OK) return;
  t->pubdone_pending  = 1;
  t->pubdone_status   = d.status_code;
  t->pubdone_streams  = d.stream_count;
  t->pubdone_deadline = hub->live.last_now_ms + WIRED_MOQTRUN_PUBDONE_WAIT_MS;
  moqtrun_pubdone_try(hub, p, t);
}

/* The publisher's PUBLISH_DONE on its PUBLISH stream (the request route
 * admits it there only); on the control stream it names no PUBLISH:
 * ignored. */
void moqtrun_dispatch_pub_done(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  wired_moqtrun_track* t = moqtrun_pubdone_req_track(p);
  (void)peer_idx;
  if (t) moqtrun_pubdone_arm(hub, p, t, body);
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

/* The New Session URI for p: empty on raw QUIC. The app's one URI names
 * the WT locator, and -22 9.2 (-18/-19 10.4) says it "SHOULD use the same
 * scheme as the current URI"; a zero-length URI means "reuse the current
 * URI", valid on every transport (plan open question 5). */
static wired_span moqtrun_goaway_uri(
    const wired_moqtrun_peer* p, wired_span uri) {
  return p->raw ? wired_span_of(0, 0) : uri;
}

/* GOAWAY g in p's draft on p's control stream (10.4), noted in its
 * session state. draft-18's Request ID is the smallest one p has not
 * sent yet: the hub handles each request as it arrives. */
static void moqtrun_goaway_one(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, moqctl_goaway g, u64 deadline) {
  u8 msg[WIRED_MOQTRUN_GOAWAY_MSG_MAX];
  g.request_id      = p->peer_rid_next;
  g.new_session_uri = moqtrun_goaway_uri(p, g.new_session_uri);
  usz n             = moqtrun_envelope_put(
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
int moqtrun_goaway_send(
    wired_moqt_hub* hub, wired_wt_session* s, wired_span uri, u64 timeout_ms) {
  moqctl_goaway g        = {uri, timeout_ms, 0};
  u64           deadline = moqtrun_goaway_deadline(hub, timeout_ms);
  int           sent     = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    sent += moqtrun_goaway_try(hub, &hub->peers[i], s, g, deadline);
  return sent;
}
