/* Real-UDP MOQT chat server (draft-ietf-moq-transport-19 minimal subset).
 * libc-free, x86_64-linux, direct syscalls, driven by the single SDK header
 * <wired.h>.
 *
 * Each connected client PUBLISHes exactly one fixed-namespace track (name =
 * participant id) and SUBSCRIBEs to the others; the wired_moqt_ hub
 * (app/moqt/run/moqtrun.h) does the session/subscribe state machines and
 * the relay logic. This file only wires the WT session/stream callbacks to
 * that hub and adapts wired_server_wt_* into the hub's wired_moqt_io table.
 * Single-process driver only -- the hub keeps its peer table in one
 * process's memory (see moqtrun.h's fixed-capacity peer/sub tables), so
 * --workers/--cores multi-process drivers would each run an isolated,
 * non-communicating hub instance. */

#define WIRED_MAIN /* this TU emits the libc memcpy/memset shim */
#include "app/moqt/run/moqtrun.h"
#include "app/webtransport/wtwire/wtwire.h"
#include "common/platform/clock/mono.h"
#include "transport/recovery/congestion/cc/cc.h"
#include "wired.h"

/* --- wired_moqt_io: thin wrappers around wired_server_wt_* --------------
 *
 * moqtrun.c (app/moqt/run) never dereferences wired_wt_session -- it stays
 * session-opaque so it's testable without the QUIC/TLS stack (see
 * moqtrun.h). Prefixing the WebTransport stream signal (draft-ietf-
 * webtrans-http3-15 4.2: varint 0x41/0x54 + the session's CONNECT stream
 * id) therefore belongs here, the one place with a real wired_wt_session*
 * to read connect_stream_id from -- srvrun.h documents this as the
 * open_bidi_stream/open_uni_stream caller's responsibility. */

/* Signal prefix (<=9B) + one bidi control reply. Only the bidi control
 * path below still stages on the stack at this size; the uni open paths
 * go through g_open_buf (below), sized for a full relay round. Safe
 * because wired_server_wt_* COPY any payload that fits their own per-slot
 * staging (srvrun.h), so nothing here must outlive its call. */
#define MOQT_SIG_BUF 2048

/* Track aliases below this limit get the reliable relay; the rest stay
 * lossy. The chat tracks use aliases 0..3 -- one per entry of the
 * frontend's CANDIDATE_PARTICIPANT_IDS (4 ids, moqtClient.ts) -- while
 * voice/screen tracks (<id>/audio, <id>/screen) use higher aliases and
 * must remain lossy. */
#define CHAT_ALIAS_LIMIT 4

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
#define BIG_SLOTS                                                          \
  (WIRED_CONNTABLE_CAP < WIRED_MOQTRUN_MAX_SESSIONS ? WIRED_CONNTABLE_CAP \
                                                    : WIRED_MOQTRUN_MAX_SESSIONS)
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

/* Signal prefix + one full relay round for the uni open paths
 * (moqt_io_send_uni / moqt_io_open_uni_stream):
 *   BIG_SIG_MAX (9) + WIRED_MOQTRUN_RELAY_HDR_MAX (40)
 *   + WIRED_MOQTRUN_RELAY_FRAG_MAX (512) + WIRED_SRVLOOP_WT_BUF_CAP (49152)
 *   = 49713 bytes. Must stay below SRVRUN_WTSEND_BUF (65536, srvrun.c):
 * wired_server_wt_open_uni / wired_server_wt_open_uni_stream copy a
 * payload up to that size into their own per-slot staging DURING the
 * call, so nothing here outlives it. Single thread, synchronous
 * callbacks, no re-entry -- one static buffer (not ~50KB of stack)
 * serves every open. */
#define MOQT_OPEN_BUF                                                  \
  (BIG_SIG_MAX + WIRED_MOQTRUN_RELAY_HDR_MAX +                         \
   WIRED_MOQTRUN_RELAY_FRAG_MAX + WIRED_SRVLOOP_WT_BUF_CAP)
static u8 g_open_buf[MOQT_OPEN_BUF];

/* Decimal/string/hex line-building helpers (also used by the shutdown
 * relay-stats log below). */
static usz dec_u64(char* out, u64 v) {
  char tmp[20];
  usz  n = 0;
  do {
    tmp[n++] = (char)('0' + (v % 10));
    v /= 10;
  } while (v);
  for (usz i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
  return n;
}

static void append_cstr(char* line, usz* n, const char* s) {
  for (usz i = 0; s[i]; i++) line[(*n)++] = s[i];
}

static char hex_nibble(u8 v) {
  return (char)(v < 10 ? '0' + v : 'a' + (v - 10));
}

static i64 moqt_io_open_bidi_stream(wired_wt_session* s, wired_span payload) {
  u8  buf[MOQT_SIG_BUF];
  usz sig = wired_wtwire_signal_put(buf, sizeof buf, 1, s->connect_stream_id);
  if (sig == 0 || payload.n > sizeof buf - sig) return -1;
  for (usz i = 0; i < payload.n; i++) buf[sig + i] = payload.p[i];
  return wired_server_wt_open_bidi_stream(s, wired_span_of(buf, sig + payload.n));
}

/* The live_session owned by s, claimed on its first live send; 0 when
 * every one is taken. */
static live_session* live_session_for(wired_wt_session* s) {
  for (usz i = 0; i < BIG_SLOTS; i++)
    if (g_live[i].s == s) return &g_live[i];
  for (usz i = 0; i < BIG_SLOTS; i++)
    if (g_live[i].s == 0) return &g_live[i];
  return 0;
}

/* A slot is reusable when it was never armed, or when its recorded stream
 * is no longer in flight (its view was released -- live_session's doc). */
static int live_slot_free(const live_session* ls, const live_slot* slot) {
  return !slot->used || !wired_server_wt_stream_inflight(ls->s, slot->stream_id);
}

static live_slot* live_slot_claim(live_session* ls) {
  for (usz i = 0; i < LIVE_RING; i++)
    if (live_slot_free(ls, &ls->ring[i])) return &ls->ring[i];
  return 0;
}

/* wired_moqt_io.send_uni2-shaped: signal prefix + head + body staged into
 * one of the session's ring slots, handed to wired_server_wt_open_uni as
 * a view (live_session's doc). */
static i64 moqt_io_send_uni2(
    wired_wt_session* s, wired_span head, wired_span body) {
  live_session* ls   = live_session_for(s);
  live_slot*    slot = ls ? live_slot_claim(ls) : 0;
  if (!slot || head.n + body.n > sizeof slot->buf - BIG_SIG_MAX) return -1;
  usz sig = wired_wtwire_signal_put(
      slot->buf, BIG_SIG_MAX, 0, s->connect_stream_id);
  if (sig == 0) return -1;
  bytes_memcpy(slot->buf + sig, head.p, head.n);
  bytes_memcpy(slot->buf + sig + head.n, body.p, body.n);
  i64 sid = wired_server_wt_open_uni(
      s, wired_span_of(slot->buf, sig + head.n + body.n));
  if (sid >= 0) {
    ls->s           = s;
    slot->stream_id = (u64)sid;
    slot->used      = 1;
  }
  return sid;
}

static void live_session_release(wired_wt_session* s) {
  for (usz i = 0; i < BIG_SLOTS; i++)
    if (g_live[i].s == s) {
      g_live[i].s = 0;
      for (usz j = 0; j < LIVE_RING; j++) g_live[i].ring[j].used = 0;
    }
}

/* One-shot open+send+FIN (wired_server_wt_open_uni-shaped): used for a
 * relayed Object, which always completes in its stream's only round -- see
 * moqtrun.h's send_uni doc for why this must not go through
 * open_uni_stream + a bare stream_send(fin=1) instead. A payload past
 * g_open_buf's relay-round staging is refused; live fragments go through
 * send_uni2's staging ring instead. */
static i64 moqt_io_send_uni(wired_wt_session* s, wired_span payload) {
  usz sig = wired_wtwire_signal_put(
      g_open_buf, sizeof g_open_buf, 0, s->connect_stream_id);
  if (sig == 0 || payload.n > sizeof g_open_buf - sig) return -1;
  bytes_memcpy(g_open_buf + sig, payload.p, payload.n);
  return wired_server_wt_open_uni(
      s, wired_span_of(g_open_buf, sig + payload.n));
}

/* wired_wt_on_session_close-shaped: frees the session's staging ring (its
 * views are dead with the connection) before the hub forgets the peer. */
static void on_session_close(void* ctx, wired_wt_session* s) {
  live_session_release(s);
  wired_moqt_on_session_close(ctx, s);
}

/* wired_server_wt_open_uni_stream-shaped: opens WITHOUT FIN and keeps the
 * stream open for further stream_send rounds -- used to start a
 * subscriber's keep-open relay stream (moqtrun.h's open_uni_stream doc).
 * Appends need no wrapper at all: the SDK copies each accepted round into
 * the stream's own send-slot staging and pipelines it behind unACKed
 * rounds (srvrun.h), so the io table points straight at
 * wired_server_wt_stream_send / wired_server_wt_stream_fin. */
static i64 moqt_io_open_uni_stream(wired_wt_session* s, wired_span payload) {
  usz sig = wired_wtwire_signal_put(
      g_open_buf, sizeof g_open_buf, 0, s->connect_stream_id);
  if (sig == 0 || payload.n > sizeof g_open_buf - sig) return -1;
  bytes_memcpy(g_open_buf + sig, payload.p, payload.n);
  return wired_server_wt_open_uni_stream(
      s, wired_span_of(g_open_buf, sig + payload.n));
}

/* wired_moqt_io.send_budget-shaped: remaining session-level send credit
 * in bytes. sent_data is charged when a send is staged (session.h), so
 * max_data - sent_data already excludes staged-but-unsent bytes; a peer
 * that never announced WT_MAX_DATA (max_data == 0) has no limit. */
static usz moqt_io_send_budget(wired_wt_session* s) {
  if (s->max_data == 0) return (usz)-1;
  return s->max_data > s->sent_data ? s->max_data - s->sent_data : 0;
}

static const wired_moqt_io g_moqt_io = {
    moqt_io_open_bidi_stream,
    wired_server_wt_stream_send,
    moqt_io_send_uni,
    moqt_io_open_uni_stream,
    wired_server_wt_stream_fin,
    wired_server_wt_stream_reset,
    moqt_io_send_uni2,
    /* send_datagram needs no wrapper: unlike the stream entries there is
     * no WebTransport signal prefix to add (the SDK applies the RFC 9297
     * quarter-stream-id itself), so the io shape matches exactly. */
    wired_server_wt_send_datagram_to,
    /* stream_hold needs no wrapper either: it toggles retransmission
     * shedding on an already-open stream, so there is no signal prefix
     * to add and the io shape matches srvrun.h exactly. */
    wired_server_wt_stream_hold,
    moqt_io_send_budget,
};

static wired_moqt_hub g_hub;

/* --- Plain HTTP/3 app: identical shape to examples/webtransport_echo ---- */

static int app_on_request(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    wired_obuf*                  body_out,
    const char**                content_type,
    int*                        more,
    u64*                        total_size) {
  static const u8 body[] =
      "moqt_chat: connect via WebTransport (subprotocol moqt-19) to join "
      "the chat room. Each participant PUBLISHes one track and SUBSCRIBEs "
      "to every other participant's track (draft-ietf-moq-transport-19).\n";
  usz i;
  (void)ctx;
  (void)req;
  (void)offset;
  (void)more;
  (void)total_size;
  *content_type = "text/plain";
  for (i = 0; i < sizeof body - 1 && i < body_out->cap; i++)
    body_out->p[i] = body[i];
  body_out->len = i;
  return 1;
}

/* Fixed, deterministic server identity for wired_server_run_opt (same recipe
 * as webtransport_chat/word_list: a demo needs no key rotation). */
static const u8 SERVER_SCID[6] = {'M', 'O', 'Q', 'C', 'H', 'T'};

typedef struct {
  u8 priv[32];
  u8 pub[32];
  u8 seed[32];
  u8 rnd[32];
  u8 san_ipv4[4];
} server_keys;

static void server_identity(
    wired_srvboot_id* id, server_keys* k, int have_san_ipv4, u64 now_secs) {
  for (usz i = 0; i < 32; i++) {
    k->priv[i] = (u8)(0x50 + i);
    k->seed[i] = (u8)(0x90 + i);
    k->rnd[i]  = (u8)(0xb0 + i);
  }
  wired_x25519_base(k->pub, k->priv);
  id->priv                    = k->priv;
  id->pub                     = k->pub;
  id->cert_seed               = k->seed;
  id->scid                    = SERVER_SCID;
  id->scid_len                = sizeof SERVER_SCID;
  id->random                  = k->rnd;
  id->chain                   = 0; /* self-signed */
  id->chain_count             = 0;
  id->max_data                = 0;
  id->max_streams_bidi        = 0;
  id->max_datagram_frame_size = 65535;
  id->san_ipv4                = have_san_ipv4 ? k->san_ipv4 : 0;
  id->now_secs                = now_secs;
}

/* --- Startup cert fingerprint log (same recipe as webtransport_chat) ---- */

static usz hex_fingerprint(const u8 digest[32], char* out) {
  usz n = 0;
  for (usz i = 0; i < 32; i++) {
    if (i != 0) out[n++] = ':';
    out[n++] = hex_nibble((u8)(digest[i] >> 4));
    out[n++] = hex_nibble((u8)(digest[i] & 0xf));
  }
  return n;
}

static void log_cert_fingerprint(const wired_srvboot_id* id) {
  static wired_server  s;
  wired_server_init_in in = {id->priv,    id->pub,         id->cert_seed,
                             id->chain,   id->chain_count, id->san_ipv4,
                             id->now_secs, 0};
  u8                   digest[32];
  char                 line[32 + 32 * 3 + 2];
  usz                  n = 0;

  wired_server_init(&s, &in);
  if (s.sdrv.cert_count == 0) wired_die("cert build failed\n");
  wired_sha256(s.sdrv.certs[0].p, s.sdrv.certs[0].n, digest);

  {
    static const char prefix[] = "cert sha-256 fingerprint: ";
    for (; prefix[n] != 0; n++) line[n] = prefix[n];
  }
  n += hex_fingerprint(digest, line + n);
  line[n++] = '\n';
  line[n]   = 0;
  wired_log_str(line);
}

/* --- Shutdown relay-stats log ------------------------------------------ */

/* One line at shutdown with the hub's cumulative relay outcomes, so a
 * measurement run can compare server-side drops against the receivers' own
 * sequence gaps. */
static void log_relay_stats(const wired_moqt_hub* hub) {
  char line[480]; /* 13 labels (152 chars) + 13 u64s at 20 digits (260) +
                     newline/NUL = 414 worst case; 480 keeps headroom */
  usz  n = 0;
  append_cstr(line, &n, "moqt relay: sent=");
  n += dec_u64(line + n, hub->stat_relay_sent);
  append_cstr(line, &n, " dropped=");
  n += dec_u64(line + n, hub->stat_relay_drop);
  append_cstr(line, &n, " frag_dropped=");
  n += dec_u64(line + n, hub->stat_frag_drop);
  append_cstr(line, &n, " open_dropped=");
  n += dec_u64(line + n, hub->stat_open_drop);
  append_cstr(line, &n, " reset=");
  n += dec_u64(line + n, hub->stat_relay_reset);
  append_cstr(line, &n, " relay_full=");
  n += dec_u64(line + n, hub->stat_relay_full);
  append_cstr(line, &n, " live_sent=");
  n += dec_u64(line + n, hub->stat_live_sent);
  append_cstr(line, &n, " live_dropped=");
  n += dec_u64(line + n, hub->stat_live_drop);
  append_cstr(line, &n, " dg_sent=");
  n += dec_u64(line + n, hub->stat_dg_sent);
  append_cstr(line, &n, " dg_dropped=");
  n += dec_u64(line + n, hub->stat_dg_drop);
  append_cstr(line, &n, " dg_bad=");
  n += dec_u64(line + n, hub->stat_dg_bad);
  append_cstr(line, &n, " rel_stall=");
  n += dec_u64(line + n, hub->stat_rel_stall);
  append_cstr(line, &n, " rel_overflow=");
  n += dec_u64(line + n, hub->stat_rel_overflow);
  line[n++] = '\n';
  line[n]   = 0;
  wired_log_str(line);
}

/* wired_srvrun_on_step-shaped: paces the hub's live track (moqtrun.h's
 * wired_moqt_tick doc). ctx is the hub. */
static void on_step(void* ctx, u64 now_ms) {
  wired_moqt_tick((wired_moqt_hub*)ctx, now_ms);
}

static void load_san_ipv4(int argc, char** argv, u8 san_ipv4[4], int* have_it) {
  const char* ip_str = wired_cliargs_str(argc, argv, "--san-ipv4", 0);
  *have_it           = ip_str != 0;
  if (ip_str && !wired_cliargs_ipv4(ip_str, san_ipv4))
    wired_die("--san-ipv4: expected dotted-quad a.b.c.d\n");
}

/* --cc cubic|bbr: parsed into CC_ALGO_* (cc.h) for wired_srvrun_obs.cc_algo.
 * NewReno is not selectable here -- CC_ALGO_NEWRENO == 0 is also "unset" in
 * that field (srvrun.h), so a runtime "--cc newreno" would be silently
 * indistinguishable from the default and is refused instead. */
static int cliarg_streq(const char* a, const char* b) {
  usz i = 0;
  for (; a[i] == b[i]; i++)
    if (a[i] == 0) return 1;
  return 0;
}

static int cc_algo_of(const char* name) {
  static const struct {
    const char* name;
    int         algo;
  } table[] = {{"cubic", CC_ALGO_CUBIC}, {"bbr", CC_ALGO_BBR}};
  for (usz i = 0; i < sizeof table / sizeof table[0]; i++)
    if (cliarg_streq(name, table[i].name)) return table[i].algo;
  wired_die(
      "--cc: expected cubic or bbr (NewReno is not selectable via --cc)\n");
  return 0;
}

__attribute__((force_align_arg_pointer, used)) int wired_main(
    int argc, char** argv) {
  wired_srvboot_id     id = {0};
  server_keys          keys;
  wired_srvdriver_opt  opt;
  int                  have_san_ipv4;
  u64                  now_secs = wired_clock_epoch_secs();
  /* Round down to the start of the UTC day: the cert (and thus the SHA-256
   * fingerprint the frontend's auto-rejoin pins via serverCertificateHashes)
   * is the only thing that changes across a same-day restart otherwise.
   * p256cert's 1h backdate + 14-day cap (tbs.c) still holds since this only
   * ever moves now_secs earlier within the same day; a restart after UTC
   * midnight still needs a manual rejoin with the new hash. */
  now_secs -= now_secs % 86400;
  wired_srvrun_handler h        = {app_on_request, 0};
  wired_srvrun_obs     obs      = {
      wired_cliargs_str(argc, argv, "--qlog", 0),
      wired_cliargs_str(argc, argv, "--keylog", 0), 0, 0,
      cc_algo_of(wired_cliargs_str(argc, argv, "--cc", "cubic"))};

  load_san_ipv4(argc, argv, keys.san_ipv4, &have_san_ipv4);
  server_identity(&id, &keys, have_san_ipv4, now_secs);
  log_cert_fingerprint(&id);

  wired_moqt_init(&g_hub, g_moqt_io);
  g_hub.reliable_alias_limit = CHAT_ALIAS_LIMIT;

  if (!wired_srvdriver_parse(argc, argv, &opt))
    wired_die(
        "bad CLI flags (moqt_chat is single-process only: do not pass "
        "--workers/--cores/--ifindex)\n");
  opt.run.incoming_cpu      = -1;
  opt.run.wt_on_session     = wired_moqt_on_session;
  opt.run.wt_session_ctx    = &g_hub;
  opt.run.wt_on_stream_data = wired_moqt_on_stream_data;
  opt.run.wt_stream_data_ctx = &g_hub;
  opt.run.wt_on_datagram    = wired_moqt_on_datagram;
  opt.run.wt_datagram_ctx   = &g_hub;
  /* Without this, a session ended server-side (idle timeout after a network
   * drop, CONNECT stream close, ...) leaks its hub peer slot forever, and a
   * reconnecting client whose new session reuses the same slot memory is
   * mistaken for the dead peer -- it never receives SETUP again. */
  opt.run.wt_on_session_close  = on_session_close;
  opt.run.wt_session_close_ctx = &g_hub;
  opt.run.on_step              = on_step;
  opt.run.on_step_ctx          = &g_hub;

  if (!wired_srvdriver_run(&id, h, obs, &opt)) wired_die("listen failed\n");
  log_relay_stats(&g_hub);
  return 0;
}
