#include "app/http3/server/srvrun/srvrun_impl.h"

static int wt_slot_is_connect_id(const srvrun_conn* c, int i, u64 stream_id);
static int srvrun_wt_conn_flow_control(const srvrun_conn* c);
static int srvrun_wt_free_slot_any(const srvrun_conn* c);
static int srvrun_wt_single_session_full(const srvrun_conn* c);
static int srvrun_wt_signal_session(const u8* sig, u8 have, u64* sid);
static int srvrun_wt_owner_live(const srvrun_conn* c, int offered, int owner);

/* Index-based view over the two physical slots (wt/wt_active, wt1/wt1_active)
 * so every routing helper below can loop 0..SRVRUN_MAX_WT_SESSIONS uniformly
 * instead of hand-unrolling both cases. c is never NULL in this file's own
 * call sites (every caller already holds a live srvrun_conn*); i is always
 * either 0 or 1 in-bounds since every caller loops against
 * SRVRUN_MAX_WT_SESSIONS==2. */
wired_wt_session* srvrun_wt_slot(srvrun_conn* c, int i) {
  return i == 0 ? &c->wt : &c->wt1;
}

int* srvrun_wt_active_slot(srvrun_conn* c, int i) {
  return i == 0 ? &c->wt_active : &c->wt1_active;
}

/* const-correct sibling of srvrun_wt_slot for read-only callers. */
const wired_wt_session* srvrun_wt_slot_c(const srvrun_conn* c, int i) {
  return i == 0 ? &c->wt : &c->wt1;
}

int srvrun_wt_is_active(const srvrun_conn* c, int i) {
  return i == 0 ? c->wt_active : c->wt1_active;
}

/* The session slot index whose OWN connect_stream_id equals stream_id and is
 * currently active, or -1 if none (draft-ietf-webtrans-http3-15 SS4.3 / RFC
 * 9220 3: a WebTransport session's identity IS its CONNECT stream's id, so
 * this is the routing key every stream/datagram reference resolves through).
 * A stream_id with no matching active slot is a foreign reference: the
 * caller must not route it to any session. */
static int wt_slot_is_connect_id(const srvrun_conn* c, int i, u64 stream_id) {
  return srvrun_wt_is_active(c, i) &&
         srvrun_wt_slot_c(c, i)->connect_stream_id == stream_id;
}

int srvrun_wt_slot_by_connect_id(const srvrun_conn* c, u64 stream_id) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++)
    if (wt_slot_is_connect_id(c, i, stream_id)) return i;
  return -1;
}

/* draft-ietf-webtrans-http3-16 SS5.1: 1 iff this connection has flow control
 * enabled -- both endpoints sent a non-zero SETTINGS_WT_INITIAL_*; this
 * server always does (control_settings.c), so the client's own SETTINGS
 * (latched connection-wide in peer_wt_initial, priority_ctrl.c) decide.
 * Every session on one connection shares this: SS5.1 names it per
 * connection ("allows a WebTransport session to share an underlying
 * transport connection with other WebTransport sessions"), and the client's
 * SETTINGS are sent once, so there is nothing session-specific to read
 * before the session itself exists (srvrun_wt_seed_limits applies the SAME
 * three values to every slot's own wired_wt_session.flow_control). */
static int srvrun_wt_conn_flow_control(const srvrun_conn* c) {
  const u64* v = c->l.peer_wt_initial;
  return (v[0] | v[1] | v[2]) != 0;
}

/* The first currently-inactive session slot among all SRVRUN_MAX_WT_SESSIONS,
 * or -1 if every one holds an open session. */
static int srvrun_wt_free_slot_any(const srvrun_conn* c) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++)
    if (!srvrun_wt_is_active(c, i)) return i;
  return -1;
}

/* draft-ietf-webtrans-http3-16 SS5.1: 1 iff flow control is disabled on this
 * connection AND a session is already active -- at most one WebTransport
 * session is ever allowed without it, so a second is never a free slot
 * regardless of SRVRUN_MAX_WT_SESSIONS. */
static int srvrun_wt_single_session_full(const srvrun_conn* c) {
  return !srvrun_wt_conn_flow_control(c) && c->wt_active;
}

/* The first currently-inactive session slot, or -1 if every slot holds an
 * open session (SRVRUN_MAX_WT_SESSIONS reached), or -- SS5.1 -- flow
 * control is disabled on this connection and a session is already active.
 * The accept-path capacity check (accept below the limit, reject at it) and
 * the reuse point once a slot frees. */
int srvrun_wt_free_slot(const srvrun_conn* c) {
  if (srvrun_wt_single_session_full(c)) return -1;
  return srvrun_wt_free_slot_any(c);
}

/* Active WT sessions (both slots) across every connection of env. */
usz srvrun_wt_active_total(const wired_srvrun_env* env) {
  usz n = 0;
  for (usz i = 0; i < WIRED_CONNTABLE_CAP; i++)
    n += (usz)env->conns[i].wt_active + (usz)env->conns[i].wt1_active;
  return n;
}

/* RFC 9114 10.5.2: 1 if a new session cannot open -- c's own slots are all
 * taken, or SRVRUN_MAX_WT_SESSIONS_GLOBAL is reached server-wide. */
int srvrun_wt_no_room(const srvrun_cfg* cfg, const srvrun_conn* c) {
  return srvrun_wt_free_slot(c) < 0 ||
         srvrun_wt_active_total(cfg->env) >= SRVRUN_MAX_WT_SESSIONS_GLOBAL ||
         c->wt_sess_window_count >= SRVRUN_MAX_WT_SESSIONS_PER_WINDOW;
}

/* The first active session slot, -1 if none: the target of a stream that
 * carries no signal (raw QUIC's implicit session). */
int srvrun_wt_slot_for_new_stream(const srvrun_conn* c) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++)
    if (srvrun_wt_is_active(c, i)) return i;
  return -1;
}

/* draft-ietf-webtrans-http3-15 4.3: the Session ID a stream's signal names
 * -- the second varint of the leading signal bytes sig[0..have) (the first
 * is the 0x41/0x54 type). 1 with *sid set, 0 when there is no signal. */
static int srvrun_wt_signal_session(const u8* sig, u8 have, u64* sid) {
  usz        off = 0;
  wired_span s   = wired_span_of(sig, have);
  if (!varint_take(s, &off, sid)) return 0;
  return varint_take(s, &off, sid);
}

/* The session slot a new WT stream belongs to: the live session whose
 * CONNECT stream its signal names (a stream naming no live session goes
 * to none, -1), or -- no signal at all (raw QUIC) -- the first active one. */
int srvrun_wt_slot_for_signal(const srvrun_conn* c, const u8* sig, u8 have) {
  u64 sid;
  if (!srvrun_wt_signal_session(sig, have, &sid))
    return srvrun_wt_slot_for_new_stream(c);
  return srvrun_wt_slot_by_connect_id(c, sid);
}

/* 1 iff a stream offered (offered) to session slot owner may still deliver
 * there: that session is still open. A closed session's own streams were
 * reset and freed with it (srvrun_close_wt_session_slot), and a closing
 * connection has no open session left (srvrun_close_send). */
static int srvrun_wt_owner_live(const srvrun_conn* c, int offered, int owner) {
  return offered && srvrun_wt_is_active(c, owner);
}

/* The session slot a WT stream delivers to: the one it was offered to
 * (wt_session_slot, recorded at offer time), never a fresh first-active
 * lookup -- once that slot closes and an Extended CONNECT reuses it, a
 * recompute would hand one session's bytes to another (TLA+ MoqtRawConn D1,
 * wtroute DeliverToOwner). -1 when nothing may be delivered. */
int srvrun_wt_stream_owner(const srvrun_conn* c, int offered, int owner) {
  return srvrun_wt_owner_live(c, offered, owner) ? owner : -1;
}

/* Free a WT bidi slot whose stream has ended, owing the peer one stream of
 * bidi credit back if the stream was client-initiated (RFC 9000 2.1: the
 * low bit clear) -- a server-opened stream never consumed it. */
void srvrun_wt_bidi_slot_free(
    srvrun_conn* c, wired_srvloop_wt_stream_slot* slot) {
  c->wt_bidi_credit_owed += !(slot->stream_id & 1);
  /* records the id as closed, so a late frame cannot reopen it */
  wired_srvloop_wt_slot_release(&c->l, slot->stream_id);
}
