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
#include "common/platform/clock/mono.h"
#include "moqt_chat.h"
#include "transport/recovery/congestion/cc/cc.h"

/* Track aliases below this limit get the reliable relay; the rest stay
 * lossy. The chat tracks use aliases 0..3 -- one per entry of the
 * frontend's CANDIDATE_PARTICIPANT_IDS (4 ids, moqtClient.ts) -- while
 * voice/screen tracks (<id>/audio, <id>/screen) use higher aliases and
 * must remain lossy. */
#define CHAT_ALIAS_LIMIT 4

static wired_moqt_hub g_hub;

/* Object cache for history (draft-ietf-moq-transport-22 3.4 fill fetch
 * streams; draft-19 10.12.3 Joining FETCH on the legacy session): chat
 * history and a video late-joiner's keyframe group are served from it. One
 * arena for every track, oldest whole group evicted first (moqcache.h), so
 * a busy screen share pushes chat history out first. */
#define MOQT_CACHE_BYTES (1u << 20)
static u8 g_cache_arena[MOQT_CACHE_BYTES];

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

static void load_san_ipv4(int argc, char** argv, u8 san_ipv4[4], int* have_it) {
  const char* ip_str = wired_cliargs_str(argc, argv, "--san-ipv4", 0);
  *have_it           = ip_str != 0;
  if (ip_str && !wired_cliargs_ipv4(ip_str, san_ipv4)) {
    wired_die("--san-ipv4: expected dotted-quad a.b.c.d\n");
  }
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
  for (usz i = 0; i < sizeof table / sizeof table[0]; i++) {
    if (wired_cstr_eq(name, table[i].name)) {
      return table[i].algo;
    }
  }
  wired_die(
      "--cc: expected cubic or bbr (NewReno is not selectable via --cc)\n");
  return 0;
}

/* --qlog/--keylog observers and the --cc algorithm (cert paths later). */
static wired_srvrun_obs cli_obs(int argc, char** argv) {
  return (wired_srvrun_obs){
      wired_cliargs_str(argc, argv, "--qlog", 0),
      wired_cliargs_str(argc, argv, "--keylog", 0), 0, 0,
      cc_algo_of(wired_cliargs_str(argc, argv, "--cc", "cubic"))};
}

/* Now, rounded down to the start of the UTC day: the cert (and thus the
 * SHA-256 fingerprint the frontend's auto-rejoin pins via
 * serverCertificateHashes) is the only thing that changes across a same-day
 * restart otherwise. p256cert's 1h backdate + 14-day cap (tbs.c) still
 * holds since this only ever moves now_secs earlier within the same day; a
 * restart after UTC midnight still needs a manual rejoin with the new
 * hash. */
static u64 day_start_secs(void) {
  u64 now_secs = wired_clock_epoch_secs();
  return now_secs - now_secs % 86400;
}

/* --cert/--key (or WIRED_CERT/WIRED_KEY): a PEM pair replaces the
 * in-memory self-signed identity, and SIGHUP re-reads the same paths
 * (srvrun.h's wired_srvrun_obs) without dropping a connection. */
static void cert_setup(
    wired_srvboot_id* id, wired_srvrun_obs* obs, int argc, char** argv) {
  static wired_certreload_store cert_store;
  obs->cert_path = wired_cliargs_str(
      argc, argv, "--cert", wired_envp_get(argc, argv, "WIRED_CERT"));
  obs->key_path = wired_cliargs_str(
      argc, argv, "--key", wired_envp_get(argc, argv, "WIRED_KEY"));
  wired_certreload_load_or_selfsigned(
      obs->cert_path, obs->key_path, &cert_store, id);
  if (!wired_srvboot_log_fingerprint(2, id)) {
    wired_die("cert build failed\n");
  }
}

/* The hub: io with the staged send_uni2, the chat relay policy, the
 * history cache and the room's namespace check. */
static void hub_setup(void) {
  /* Experimental moqtail-compatible track switching (draft-22 only):
   * SWITCH_FROM for the screen-quality selector, and SSTS so the hub
   * forwards one screen variant (hi or lo) per group. Backpressure first,
   * the default allocation as the fallback. */
  static const u64 chat_ssts_algs[] = {
      MOQCTL_SSTS_ALG_BACKPRESSURE, MOQCTL_SSTS_ALG_DEFAULT};
  wired_moqt_io io = wired_moqraw_io();
  io.send_uni2     = chat_send_uni2;
  wired_moqt_init(&g_hub, io);
  g_hub.reliable_alias_limit = CHAT_ALIAS_LIMIT;
  /* Live voice/video: a newer Group outranks the rest of an older one. */
  g_hub.newest_group_only = 1;
  wired_moqt_cache_attach(&g_hub, g_cache_arena, sizeof g_cache_arena);
  g_hub.authorize_namespace = chat_authorize_room_ns;
  g_hub.switch_track        = 1;
  g_hub.ssts_algs           = chat_ssts_algs;
  g_hub.ssts_alg_n          = sizeof chat_ssts_algs / sizeof chat_ssts_algs[0];
}

/* Routes the WebTransport session callbacks to the hub (via relay.c's
 * counting wrappers for open/close). */
static void hub_callbacks(wired_srvrun_opt* run) {
  run->wt_on_session      = chat_on_session;
  run->wt_session_ctx     = &g_hub;
  run->wt_on_stream_data  = wired_moqt_on_stream_data;
  run->wt_stream_data_ctx = &g_hub;
  run->wt_on_datagram     = wired_moqt_on_datagram;
  run->wt_datagram_ctx    = &g_hub;
  /* A reset request stream cancels its request (subscription/track). */
  run->wt_on_stream_reset  = wired_moqt_on_stream_reset;
  run->wt_stream_reset_ctx = &g_hub;
  /* Without this, a session ended server-side (idle timeout after a network
   * drop, CONNECT stream close, ...) leaks its hub peer slot forever, and a
   * reconnecting client whose new session reuses the same slot memory is
   * mistaken for the dead peer -- it never receives SETUP again. */
  run->wt_on_session_close  = chat_on_session_close;
  run->wt_session_close_ctx = &g_hub;
  /* A peer's WT_DRAIN_SESSION drains its MOQT session (GOAWAY). */
  run->wt_on_session_draining  = wired_moqt_on_session_draining;
  run->wt_session_draining_ctx = &g_hub;
  run->on_step                 = chat_on_step;
  run->on_step_ctx             = &g_hub;
}

/* Driver flags (single-process only), the offered subprotocols, and the
 * hub and origin callbacks. */
static void run_setup(wired_srvdriver_opt* opt, int argc, char** argv) {
  /* draft-22 6.2.1: the WebTransport subprotocols offered ("moqt-22
   * moqt-19 moqt-18"); none negotiated = the draft-19 legacy session. */
  static char wt_protocols[32];
  if (!wired_srvdriver_parse(argc, argv, opt)) {
    wired_die(
        "bad CLI flags (moqt_chat is single-process only: do not pass "
        "--workers/--cores/--ifindex)\n");
  }
  if (!wired_moqt_wt_protocols(wt_protocols, sizeof wt_protocols)) {
    wired_die("wt_protocols buffer too small\n");
  }
  opt->run.wt_protocols = wt_protocols;
  opt->run.incoming_cpu = -1;
  hub_callbacks(&opt->run);
  chat_origin_setup(&opt->run, argc, argv);
}

__attribute__((force_align_arg_pointer, used)) int wired_main(
    int argc, char** argv) {
  wired_srvboot_id     id = {0};
  server_keys          keys;
  wired_srvdriver_opt  opt;
  int                  have_san_ipv4;
  wired_srvrun_handler h   = {.cb = app_on_request};
  wired_srvrun_obs     obs = cli_obs(argc, argv);

  load_san_ipv4(argc, argv, keys.san_ipv4, &have_san_ipv4);
  server_identity(&id, &keys, have_san_ipv4, day_start_secs());
  cert_setup(&id, &obs, argc, argv);
  chat_goaway_setup(argc, argv);
  hub_setup();
  run_setup(&opt, argc, argv);

  if (!wired_srvdriver_run(&id, h, obs, &opt)) {
    wired_die("listen failed\n");
  }
  chat_log_relay_stats(&g_hub, "moqt relay: ");
  return 0;
}
