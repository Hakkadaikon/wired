/* moqt_chat's send_uni2: live fragments staged in a per-session ring.
 *
 * The hub's io table is the SDK's transport mux wired_moqraw_io
 * (app/moqt/qraw/moqrawio.h): it prefixes the WebTransport stream signal
 * (draft-ietf-webtrans-http3-15 4.2) on the stream-opening ops and maps the
 * rest straight to wired_server_wt_*. This file adds only send_uni2, whose
 * live fragments need per-session staging (live_session below). */

#include "app/moqt/qraw/moqrawio.h"
#include "app/webtransport/wtwire/wtwire.h"
#include "moqt_chat.h"
#include "transport/conn/lifecycle/conntable/conntable.h"

/* Per-session staging ring for live fragments: wired_server_wt_open_uni
 * holds a payload above its 4096-byte staging as a VIEW until every byte
 * is ACKed (srvrun.h), and the WebTransport signal prefix -- different
 * per session, it carries the CONNECT stream id -- must sit contiguously
 * in front of it. So each session gets LIVE_RING slots of LIVE_FRAG_MAX
 * here; a slot is reusable only once wired_server_wt_stream_inflight
 * reports its recorded stream done (the view is free then), and a session
 * close frees all of its slots at once (on_session_close, the one point
 * this file learns every view is dead). Three slots: with 2-second Groups
 * a fragment is normally ACKed long before two successors have been
 * paced out, so a full ring means a genuinely stalled subscriber -- the
 * hub counts the refused send on stat_live_drop and moves on. Live
 * sessions are bounded by both the connection table and the hub's peer
 * table, so the smaller of the two is enough sessions. */
#define LIVE_RING 3
#define LIVE_FRAG_MAX (1u << 20)
#define BIG_SIG_MAX 9
enum {
  BIG_SLOTS = WIRED_CONNTABLE_CAP < WIRED_MOQTRUN_MAX_SESSIONS
                  ? WIRED_CONNTABLE_CAP
                  : WIRED_MOQTRUN_MAX_SESSIONS
};
typedef struct {
  u64 stream_id;
  int used;
  u8  buf[BIG_SIG_MAX + MOQDATA_MSG_OVERHEAD + LIVE_FRAG_MAX];
} live_slot;
typedef struct {
  wired_wt_session* s; /* owning session, 0 = free */
  live_slot         ring[LIVE_RING];
} live_session;
static live_session g_live[BIG_SLOTS];

/* The live_session owned by s (s == 0: the first free one), or 0. */
static live_session* live_find(const wired_wt_session* s) {
  for (usz i = 0; i < BIG_SLOTS; i++) {
    if (g_live[i].s == s) {
      return &g_live[i];
    }
  }
  return 0;
}

/* The live_session owned by s, claimed on its first live send; 0 when
 * every one is taken. */
static live_session* live_session_for(const wired_wt_session* s) {
  live_session* ls = live_find(s);
  return ls ? ls : live_find(0);
}

/* A slot is reusable when it was never armed, or when its recorded stream
 * is no longer in flight (its view was released -- live_session's doc). */
static int live_slot_free(const live_session* ls, const live_slot* slot) {
  return !slot->used ||
         !wired_server_wt_stream_inflight(ls->s, slot->stream_id);
}

static live_slot* live_slot_claim(live_session* ls) {
  for (usz i = 0; i < LIVE_RING; i++) {
    if (live_slot_free(ls, &ls->ring[i])) {
      return &ls->ring[i];
    }
  }
  return 0;
}

/* 1 when slot exists and n payload bytes fit behind the signal prefix. */
static int live_fits(const live_slot* slot, usz n) {
  return slot && n <= sizeof slot->buf - BIG_SIG_MAX;
}

/* Signal prefix + head + body staged into slot, opened as a uni stream; on
 * success the slot (and its session, on a first send) is armed. */
static i64 live_stage(
    live_session*     ls,
    live_slot*        slot,
    wired_wt_session* s,
    wired_span        head,
    wired_span        body) {
  usz sig =
      wired_wtwire_signal_put(slot->buf, BIG_SIG_MAX, 0, s->connect_stream_id);
  i64 sid;
  if (sig == 0) {
    return -1;
  }
  bytes_memcpy(slot->buf + sig, head.p, head.n);
  bytes_memcpy(slot->buf + sig + head.n, body.p, body.n);
  sid = wired_server_wt_open_uni(
      s, wired_span_of(slot->buf, sig + head.n + body.n));
  if (sid >= 0) {
    ls->s           = s;
    slot->stream_id = (u64)sid;
    slot->used      = 1;
  }
  return sid;
}

/* wired_moqt_io.send_uni2-shaped: signal prefix + head + body staged into
 * one of the session's ring slots, handed to wired_server_wt_open_uni as
 * a view (live_session's doc). */
i64 chat_send_uni2(wired_wt_session* s, wired_span head, wired_span body) {
  live_session* ls   = live_session_for(s);
  live_slot*    slot = ls ? live_slot_claim(ls) : 0;
  if (!live_fits(slot, head.n + body.n)) {
    return -1;
  }
  return live_stage(ls, slot, s, head, body);
}

static void live_session_free(live_session* ls) {
  ls->s = 0;
  for (usz j = 0; j < LIVE_RING; j++) {
    ls->ring[j].used = 0;
  }
}

void chat_live_release(wired_wt_session* s) {
  for (usz i = 0; i < BIG_SLOTS; i++) {
    if (g_live[i].s == s) {
      live_session_free(&g_live[i]);
    }
  }
}
