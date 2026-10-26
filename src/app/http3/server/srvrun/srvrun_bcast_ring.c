#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_bcast_ring_conn(
    wired_srvrun_env* env, int cslot, wired_span data);
static void srvrun_wt_close_record_message(
    srvrun_conn* c, int sidx, wired_span message);
static usz                  srvrun_wt_streams_open(const srvrun_conn* c);
static srvrun_dgring_entry* srvrun_dgring_at(wired_srvrun_env* env, usz i);
static int  srvrun_dgring_beats(wired_srvrun_env* env, usz i, usz best);
static usz  srvrun_dgring_best(wired_srvrun_env* env);
static int  srvrun_dgring_over_budget(usz bytes, usz len);
static void srvrun_dgring_pop_sent(wired_srvrun_env* env);

/* All of one connection's session slots, ANDing per-target success -- split
 * out of wired_server_broadcast_datagram_ring so each loop stays at the CCN
 * gate. */
static int srvrun_bcast_ring_conn(
    wired_srvrun_env* env, int cslot, wired_span data) {
  int ok = 1;
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++) {
    ok &= srvrun_bcast_ring_sess(env, cslot, i, data);
  }
  return ok;
}

int wired_server_broadcast_datagram_ring(wired_span data) {
  wired_srvrun_env* env = srvrun_caller_env();
  int               ok  = 1;
  for (usz i = 0; i < WIRED_CONNTABLE_CAP; i++) {
    ok &= srvrun_bcast_ring_conn(env, (int)i, data);
  }
  return ok;
}

/* Copy message into c's own wt_close_msg[sidx] scratch, capped at
 * WTCAPSULE_CLOSE_MESSAGE_MAX (wired_wtcapsule_encode_close's own limit,
 * wtcapsule.h) -- a longer message is truncated rather than rejected, same
 * ponytail policy as this file's other fixed-capacity copies (e.g. wt_path).
 * draft-ietf-webtrans-http3-16 SS6 (new MUST): the truncation point is the
 * last whole UTF-8 character boundary at or before the cap
 * (wtcapsule_utf8_truncate_len), not a raw byte count -- a byte cut mid
 * multi-byte sequence would hand the peer an invalid UTF-8 message. */
static void srvrun_wt_close_record_message(
    srvrun_conn* c, int sidx, wired_span message) {
  usz n = wtcapsule_utf8_truncate_len(message, WTCAPSULE_CLOSE_MESSAGE_MAX);
  bytes_memcpy(c->wt_close_msg[sidx], message.p, n);
  c->wt_close_msg_len[sidx] = n;
}

int wired_server_wt_drain_session(wired_wt_session* s) {
  srvrun_conn* c    = srvrun_session_conn(s);
  int          sidx = srvrun_wt_session_slot_or_absent(c, s);
  /* draft-ietf-moq-transport-19 3.6: raw QUIC has no WT_DRAIN_SESSION */
  if (sidx < 0 || srvrun_conn_is_raw(c)) {
    return 0;
  }
  c->wt_drain_pending[sidx] = 1;
  return 1;
}

/* Client-opened WT stream slots in use on c, 0 for a connection that is
 * down (a freed slot's tables are not cleared). */
static usz srvrun_wt_streams_open(const srvrun_conn* c) {
  return c->up ? srvrun_wt_bidi_slots_in_use(c) + srvrun_wt_uni_slots_in_use(c)
               : 0;
}

int wired_server_wt_occupancy(wired_wt_occupancy* out) {
  wired_srvrun_env* env = srvrun_caller_env();
  out->sessions         = srvrun_wt_active_total(env);
  out->sessions_cap     = SRVRUN_MAX_WT_SESSIONS_GLOBAL;
  out->peer_streams     = 0;
  for (usz i = 0; i < WIRED_CONNTABLE_CAP; i++) {
    out->peer_streams += srvrun_wt_streams_open(&env->conns[i]);
  }
  out->peer_streams_cap =
      (usz)WIRED_CONNTABLE_CAP *
      (WIRED_SRVLOOP_MAX_WT_STREAMS + WIRED_SRVLOOP_MAX_WT_UNI_STREAMS);
  return 1;
}

int wired_server_session_is_raw(wired_wt_session* s) {
  srvrun_conn* c = srvrun_session_conn(s);
  return c && srvrun_conn_is_raw(c);
}

int wired_server_wt_close_session(
    wired_wt_session* s, u32 app_error_code, wired_span message) {
  srvrun_conn* c    = srvrun_session_conn(s);
  int          sidx = srvrun_wt_session_slot_or_absent(c, s);
  if (sidx < 0) {
    return 0;
  }
  c->wt_close_code[sidx] = app_error_code;
  srvrun_wt_close_record_message(c, sidx, message);
  c->wt_close_pending[sidx] = 1;
  return 1;
}

/* Seal and send one ring entry to its target connection; a connection gone
 * down since queue time -- or replaced by another client on the same slot --
 * is skipped, and a frame the peer's advertised
 * max_datagram_frame_size rejects is dropped (RFC 9221 1: DATAGRAM delivery
 * is best-effort by design, so no retry/retention). */
void srvrun_dgring_send_one(
    const srvrun_cfg* cfg, srvrun_state* st, const srvrun_dgring_entry* e) {
  u8           out[1500];
  wired_obuf   ob = obuf_of(out, sizeof out);
  srvrun_conn* c  = &st->conns[e->conn_slot];
  if (c->up && c->gen == e->conn_gen) {
    srvrun_send_datagram_now(cfg, c, wired_span_of(e->buf, e->len), &ob);
  }
}

/* Queued entry i (0 = the ring head). */
static srvrun_dgring_entry* srvrun_dgring_at(wired_srvrun_env* env, usz i) {
  return &env->dgring[(env->dgring_head + i) % SRVRUN_DGRING_CAP];
}

/* RFC 9221 5.1: unsent entry i outranks the best so far (dgring_n = none
 * yet); an equal urgency keeps the older one. */
static int srvrun_dgring_beats(wired_srvrun_env* env, usz i, usz best) {
  const srvrun_dgring_entry* e = srvrun_dgring_at(env, i);
  return !e->sent &&
         (best == env->dgring_n ||
          dgpriority_higher(e->urgency, srvrun_dgring_at(env, best)->urgency));
}

/* The most urgent unsent entry, oldest within its urgency; dgring_n when
 * every queued entry was sent. */
static usz srvrun_dgring_best(wired_srvrun_env* env) {
  usz best = env->dgring_n;
  for (usz i = 0; i < env->dgring_n; i++) {
    if (srvrun_dgring_beats(env, i, best)) {
      best = i;
    }
  }
  return best;
}

/* An entry of len past this slice's byte budget -- never the slice's first,
 * so a datagram larger than the whole budget still drains instead of
 * wedging the ring. */
static int srvrun_dgring_over_budget(usz bytes, usz len) {
  return bytes && bytes + len > SRVRUN_DGRING_DRAIN_BYTES;
}

/* Free the sent entries at the ring head. */
static void srvrun_dgring_pop_sent(wired_srvrun_env* env) {
  while (env->dgring_n && srvrun_dgring_at(env, 0)->sent) {
    env->dgring_head = (env->dgring_head + 1) % SRVRUN_DGRING_CAP;
    env->dgring_n--;
  }
}

int srvrun_dgring_send_best(
    const srvrun_cfg* cfg, srvrun_state* st, usz* bytes) {
  wired_srvrun_env*    env = cfg->env;
  usz                  i   = srvrun_dgring_best(env);
  srvrun_dgring_entry* e;
  if (i == env->dgring_n) {
    return 0;
  }
  e = srvrun_dgring_at(env, i);
  if (srvrun_dgring_over_budget(*bytes, e->len)) {
    return 0;
  }
  srvrun_dgring_send_one(cfg, st, e);
  e->sent = 1;
  *bytes += e->len;
  srvrun_dgring_pop_sent(env);
  return 1;
}
