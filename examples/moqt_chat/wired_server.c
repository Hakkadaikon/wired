/* Real-UDP MOQT chat server (draft-ietf-moq-transport-22 minimal subset,
 * draft-19 fallback). libc-free, x86_64-linux, direct syscalls, driven by
 * the single SDK header <wired.h>.
 *
 * The draft is the WebTransport subprotocol (draft-22 6.2.1): the server
 * offers the hub's list (wired_moqt_wt_protocols: moqt-22 moqt-19
 * moqt-18), so a browser that offers "moqt-22" gets a draft-22 session
 * (one uni control stream per side, 6.3); a browser that offers no
 * subprotocol still gets the draft-19 legacy session (one server-opened
 * bidi control stream), with no branch here.
 *
 * Each connected client PUBLISHes exactly one fixed-namespace track (name =
 * participant id) and SUBSCRIBEs to the others; the wired_moqt_ hub
 * (app/moqt/run/moqtrun.h) does the session/subscribe state machines and
 * the relay logic. This file only wires the WT session/stream callbacks to
 * that hub and hands it the SDK's wired_moqraw_io table (plus send_uni2).
 * Single-process driver only -- the hub keeps its peer table in one
 * process's memory (see moqtrun.h's fixed-capacity peer/sub tables), so
 * --workers/--cores multi-process drivers would each run an isolated,
 * non-communicating hub instance. */

#define WIRED_MAIN /* this TU emits the libc memcpy/memset shim */
#include "app/moqt/qraw/moqrawio.h"
#include "app/moqt/run/moqtrun.h"
#include "app/webtransport/wtwire/wtwire.h"
#include "common/platform/clock/mono.h"
#include "transport/recovery/congestion/cc/cc.h"
#include "wired.h"

/* --- wired_moqt_io --------------------------------------------------------
 *
 * The hub's io table is the SDK's transport mux wired_moqraw_io
 * (app/moqt/qraw/moqrawio.h): it prefixes the WebTransport stream signal
 * (draft-ietf-webtrans-http3-15 4.2) on the stream-opening ops and maps the
 * rest straight to wired_server_wt_*. This file adds only send_uni2, whose
 * live fragments need per-session staging (live_session below). */

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
#define BIG_SLOTS                                   \
  (WIRED_CONNTABLE_CAP < WIRED_MOQTRUN_MAX_SESSIONS \
       ? WIRED_CONNTABLE_CAP                        \
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
  return !slot->used ||
         !wired_server_wt_stream_inflight(ls->s, slot->stream_id);
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
  usz sig =
      wired_wtwire_signal_put(slot->buf, BIG_SIG_MAX, 0, s->connect_stream_id);
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

/* Live/closed session counts for the relay-stats line: incremented and
 * decremented by the wrappers below, read by log_relay_stats. */
static u64 g_sessions_live;
static u64 g_sessions_closed;

/* wired_wt_on_session-shaped: counts the session live for the stats line,
 * then registers it with the hub. */
static void on_session(
    void* ctx, wired_wt_session* s, wired_span path, wired_span protocol) {
  g_sessions_live++;
  wired_moqt_on_session(ctx, s, path, protocol);
}

/* wired_wt_on_session_close-shaped: frees the session's staging ring (its
 * views are dead with the connection) before the hub forgets the peer. */
static void on_session_close(void* ctx, wired_wt_session* s) {
  if (g_sessions_live) g_sessions_live--;
  g_sessions_closed++;
  live_session_release(s);
  wired_moqt_on_session_close(ctx, s);
}

static wired_moqt_hub g_hub;

/* Object cache for history (draft-ietf-moq-transport-22 3.4 fill fetch
 * streams; draft-19 10.12.3 Joining FETCH on the legacy session): chat
 * history and a video late-joiner's keyframe group are served from it. One
 * arena for every track, oldest whole group evicted first (moqcache.h), so
 * a busy screen share pushes chat history out first. */
#define MOQT_CACHE_BYTES (1u << 20)
static u8 g_cache_arena[MOQT_CACHE_BYTES];

/* The room's Track Namespace prefix: every namespace a peer announces or
 * watches must sit under it (draft-ietf-moq-transport-22 9.14/9.15). */
static const char* const ROOM_NS[] = {"wired", "moqt_chat"};
#define ROOM_NS_N (sizeof ROOM_NS / sizeof ROOM_NS[0])

/* wired_moqt_authorize_ns_fn: grants a namespace under ROOM_NS only. */
static int authorize_room_ns(
    void* ctx, u64 msg_type, const moqctl_ns* ns, const moqctl_token* token) {
  (void)ctx;
  (void)msg_type;
  (void)token;
  if (ns->n < ROOM_NS_N) return 0;
  for (usz i = 0; i < ROOM_NS_N; i++)
    if (!wired_span_eq_cstr(ns->fields[i], ROOM_NS[i])) return 0;
  return 1;
}

/* draft-ietf-webtrans-http3-15 3.1 / RFC 6454: WIRED_ALLOWED_ORIGINS is a
 * comma-separated list of exact Origins (e.g. "https://a.example,https://
 * b.example"); a CONNECT whose Origin is not on it gets 403. Unset leaves
 * the check off (every Origin accepted). */
static int origin_allowed(void* ctx, wired_span origin, wired_span authority) {
  const char* list = (const char*)ctx;
  (void)authority;
  for (usz start = 0, i = 0;; i++) {
    if (list[i] != ',' && list[i] != 0) continue;
    if (wired_span_eq(
            wired_span_of((const u8*)list + start, i - start), origin))
      return 1;
    if (list[i] == 0) return 0;
    start = i + 1;
  }
}

/* --- Plain HTTP/3 app: identical shape to examples/word_list ------------ */

static int app_on_request(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    wired_obuf*                 body_out,
    const char**                content_type,
    int*                        more,
    u64*                        total_size) {
  static const u8 body[] =
      "moqt_chat: connect via WebTransport to join the chat room. Offer "
      "the subprotocol moqt-22 for a draft-ietf-moq-transport-22 session; "
      "with no subprotocol negotiated the session runs "
      "draft-ietf-moq-transport-19. Each participant PUBLISHes one track "
      "and SUBSCRIBEs to every other participant's track.\n";
  (void)ctx;
  (void)req;
  (void)offset;
  (void)more;
  (void)total_size;
  *content_type = "text/plain";
  body_out->len = 0;
  wired_obuf_put(body_out, wired_span_of(body, sizeof body - 1));
  return 1;
}

/* Fixed, deterministic server identity for wired_server_run_opt (same recipe
 * as word_list: a demo needs no key rotation). */
typedef struct {
  wired_srvboot_demo_keys demo;
  u8                      san_ipv4[4];
} server_keys;

static void server_identity(
    wired_srvboot_id* id, server_keys* k, int have_san_ipv4, u64 now_secs) {
  wired_srvboot_demo(id, &k->demo, 0x50, "MOQCHT");
  id->max_datagram_frame_size = 65535;
  id->san_ipv4                = have_san_ipv4 ? k->san_ipv4 : 0;
  id->now_secs                = now_secs;
}

/* --- Relay-stats log ---------------------------------------------------- */

/* One line with the hub's cumulative relay outcomes, so a measurement run
 * can compare server-side drops against the receivers' own sequence gaps.
 * label is "moqt relay: " at shutdown and "moqt relay(10s): " from the
 * periodic on_step timer -- one format, so log-scraping regexes match
 * both. */
static void log_relay_stats(const char* label) {
  const wired_moqt_hub* hub = &g_hub;
  char line[1024]; /* label (<=17) + 24 field labels (~290 chars) + 24
                      u64s at 20 digits (480) + newline/NUL = ~790 worst
                      case; 1024 keeps headroom */
  wired_snprintf(
      line, sizeof line,
      "%ssent=%llu dropped=%llu frag_dropped=%llu open_dropped=%llu reset=%llu "
      "relay_full=%llu live_sent=%llu live_dropped=%llu dg_sent=%llu "
      "dg_dropped=%llu dg_bad=%llu rel_stall=%llu rel_overflow=%llu "
      "sessions=%llu closed=%llu rel_wait=%llu rel_sent=%llu rel_refused=%llu "
      "rel_rings=%llu rel_in=%llu rel_fin_in=%llu rel_fin_out=%llu "
      "rel_hold=%llu rel_early=%llu\n",
      label, (u64)hub->stat_relay_sent, (u64)hub->stat_relay_drop,
      (u64)hub->stat_frag_drop, (u64)hub->stat_open_drop,
      (u64)hub->stat_relay_reset, (u64)hub->stat_relay_full,
      (u64)hub->stat_live_sent, (u64)hub->stat_live_drop,
      (u64)hub->stat_dg_sent, (u64)hub->stat_dg_drop, (u64)hub->stat_dg_bad,
      (u64)hub->stat_rel_stall, (u64)hub->stat_rel_overflow,
      (u64)g_sessions_live, (u64)g_sessions_closed, (u64)hub->stat_rel_wait,
      (u64)hub->stat_rel_sent, (u64)hub->stat_rel_refused,
      (u64)hub->stat_rel_rings, (u64)hub->stat_rel_in_bytes,
      (u64)hub->stat_rel_fin_in, (u64)hub->stat_rel_fin_out,
      (u64)hub->stat_rel_hold, (u64)hub->stat_rel_early_return);
  wired_log_str(line);
}

/* The periodic line is worth printing only while a session is live, plus
 * one more time after the last one closes (so the final closed= count
 * lands). An idle hub stays quiet: 8 hours of all-zero lines once buried
 * the startup cert fingerprint in docker logs. */
static int relay_stats_moved(void) {
  static u64 last_closed;
  int        moved = g_sessions_live != 0 || g_sessions_closed != last_closed;
  last_closed      = g_sessions_closed;
  return moved;
}

/* Graceful restart (draft-ietf-moq-transport-22 6.6.1 / 9.2): on SIGTERM
 * the SDK stops accepting connections and drains for about 5 s
 * (srvrun.c SRVRUN_DRAIN_TICKS) before it closes what is left. Within that
 * window every MOQT session is sent GOAWAY -- New Session URI from
 * WIRED_GOAWAY_URI, empty (reconnect to the same URI) when unset -- so
 * clients move to the next hub themselves; a session still open after
 * GOAWAY_TIMEOUT_MS is closed by the hub (wired_moqt_goaway). */
#define GOAWAY_TIMEOUT_MS 2000
static const char* g_goaway_uri = "";

/* Sends GOAWAY once, at the first step after a shutdown was requested.
 * ponytail: during the drain the SDK steps (and so calls on_step) only
 * when a datagram arrives; live clients ACK and send audio, so it does. */
static void goaway_on_shutdown(wired_moqt_hub* hub) {
  static int sent;
  if (sent || !*wired_srvrun_shutdown_word()) return;
  sent = 1;
  wired_moqt_goaway(hub, wired_span_cstr(g_goaway_uri), GOAWAY_TIMEOUT_MS);
  wired_log_str("moqt: shutdown requested, GOAWAY sent\n");
}

/* wired_srvrun_on_step-shaped: paces the hub's live track (moqtrun.h's
 * wired_moqt_tick doc), sends GOAWAY once a shutdown starts, and emits
 * the relay-stats line every 10 seconds while sessions are live, so a
 * deployment's docker logs show whether refusals or session drops are
 * ongoing without waiting for shutdown. ctx is the hub. */
static void on_step(void* ctx, u64 now_ms) {
  static u64 next_ms;
  wired_moqt_tick((wired_moqt_hub*)ctx, now_ms);
  goaway_on_shutdown((wired_moqt_hub*)ctx);
  if (now_ms < next_ms) return;
  next_ms = now_ms + 10000;
  if (relay_stats_moved()) log_relay_stats("moqt relay(10s): ");
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
static int cc_algo_of(const char* name) {
  static const struct {
    const char* name;
    int         algo;
  } table[] = {{"cubic", CC_ALGO_CUBIC}, {"bbr", CC_ALGO_BBR}};
  for (usz i = 0; i < sizeof table / sizeof table[0]; i++)
    if (wired_cstr_eq(name, table[i].name)) return table[i].algo;
  wired_die(
      "--cc: expected cubic or bbr (NewReno is not selectable via --cc)\n");
  return 0;
}

__attribute__((force_align_arg_pointer, used)) int wired_main(
    int argc, char** argv) {
  wired_srvboot_id    id = {0};
  server_keys         keys;
  wired_srvdriver_opt opt;
  int                 have_san_ipv4;
  u64                 now_secs = wired_clock_epoch_secs();
  /* Round down to the start of the UTC day: the cert (and thus the SHA-256
   * fingerprint the frontend's auto-rejoin pins via serverCertificateHashes)
   * is the only thing that changes across a same-day restart otherwise.
   * p256cert's 1h backdate + 14-day cap (tbs.c) still holds since this only
   * ever moves now_secs earlier within the same day; a restart after UTC
   * midnight still needs a manual rejoin with the new hash. */
  now_secs -= now_secs % 86400;
  wired_srvrun_handler h   = {.cb = app_on_request};
  wired_srvrun_obs     obs = {
      wired_cliargs_str(argc, argv, "--qlog", 0),
      wired_cliargs_str(argc, argv, "--keylog", 0), 0, 0,
      cc_algo_of(wired_cliargs_str(argc, argv, "--cc", "cubic"))};

  load_san_ipv4(argc, argv, keys.san_ipv4, &have_san_ipv4);
  server_identity(&id, &keys, have_san_ipv4, now_secs);
  /* --cert/--key (or WIRED_CERT/WIRED_KEY): a PEM pair replaces the
   * in-memory self-signed identity, and SIGHUP re-reads the same paths
   * (srvrun.h's wired_srvrun_obs) without dropping a connection. */
  static wired_certreload_store cert_store;
  obs.cert_path = wired_cliargs_str(
      argc, argv, "--cert", wired_envp_get(argc, argv, "WIRED_CERT"));
  obs.key_path = wired_cliargs_str(
      argc, argv, "--key", wired_envp_get(argc, argv, "WIRED_KEY"));
  wired_certreload_load_or_selfsigned(
      obs.cert_path, obs.key_path, &cert_store, &id);
  if (!wired_srvboot_log_fingerprint(2, &id)) wired_die("cert build failed\n");

  g_goaway_uri = wired_cliargs_str(
      argc, argv, "--goaway-uri",
      wired_envp_get(argc, argv, "WIRED_GOAWAY_URI"));
  if (!g_goaway_uri) g_goaway_uri = "";
  if (wired_cstr_len(g_goaway_uri) > WIRED_MOQTRUN_GOAWAY_URI_MAX)
    wired_die("WIRED_GOAWAY_URI: longer than 8192 bytes\n");
  wired_moqt_io io = wired_moqraw_io();
  io.send_uni2     = moqt_io_send_uni2;
  wired_moqt_init(&g_hub, io);
  g_hub.reliable_alias_limit = CHAT_ALIAS_LIMIT;
  wired_moqt_cache_attach(&g_hub, g_cache_arena, sizeof g_cache_arena);
  g_hub.authorize_namespace = authorize_room_ns;
  /* Experimental moqtail-compatible track switching (draft-22 only):
   * SWITCH_FROM for the screen-quality selector, and SSTS so the hub
   * forwards one screen variant (hi or lo) per group. Backpressure first,
   * the default allocation as the fallback. */
  static const u64 chat_ssts_algs[] = {
      MOQCTL_SSTS_ALG_BACKPRESSURE, MOQCTL_SSTS_ALG_DEFAULT};
  g_hub.switch_track = 1;
  g_hub.ssts_algs    = chat_ssts_algs;
  g_hub.ssts_alg_n   = sizeof chat_ssts_algs / sizeof chat_ssts_algs[0];

  if (!wired_srvdriver_parse(argc, argv, &opt))
    wired_die(
        "bad CLI flags (moqt_chat is single-process only: do not pass "
        "--workers/--cores/--ifindex)\n");
  /* draft-22 6.2.1: the WebTransport subprotocols offered ("moqt-22
   * moqt-19 moqt-18"); none negotiated = the draft-19 legacy session. */
  static char wt_protocols[32];
  if (!wired_moqt_wt_protocols(wt_protocols, sizeof wt_protocols))
    wired_die("wt_protocols buffer too small\n");
  opt.run.wt_protocols       = wt_protocols;
  opt.run.incoming_cpu       = -1;
  opt.run.wt_on_session      = on_session;
  opt.run.wt_session_ctx     = &g_hub;
  opt.run.wt_on_stream_data  = wired_moqt_on_stream_data;
  opt.run.wt_stream_data_ctx = &g_hub;
  opt.run.wt_on_datagram     = wired_moqt_on_datagram;
  opt.run.wt_datagram_ctx    = &g_hub;
  /* A reset request stream cancels its request (subscription/track). */
  opt.run.wt_on_stream_reset  = wired_moqt_on_stream_reset;
  opt.run.wt_stream_reset_ctx = &g_hub;
  /* Without this, a session ended server-side (idle timeout after a network
   * drop, CONNECT stream close, ...) leaks its hub peer slot forever, and a
   * reconnecting client whose new session reuses the same slot memory is
   * mistaken for the dead peer -- it never receives SETUP again. */
  opt.run.wt_on_session_close  = on_session_close;
  opt.run.wt_session_close_ctx = &g_hub;
  /* A peer's WT_DRAIN_SESSION drains its MOQT session (GOAWAY). */
  opt.run.wt_on_session_draining  = wired_moqt_on_session_draining;
  opt.run.wt_session_draining_ctx = &g_hub;
  opt.run.on_step                 = on_step;
  opt.run.on_step_ctx             = &g_hub;
  opt.run.wt_origin_ctx =
      (void*)wired_envp_get(argc, argv, "WIRED_ALLOWED_ORIGINS");
  if (opt.run.wt_origin_ctx) opt.run.wt_origin_check = origin_allowed;

  if (!wired_srvdriver_run(&id, h, obs, &opt)) wired_die("listen failed\n");
  log_relay_stats("moqt relay: ");
  return 0;
}
