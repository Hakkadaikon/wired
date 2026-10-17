/* moqt_chat's session counting, graceful-restart GOAWAY and the periodic
 * relay-stats log line. */

#include "moqt_chat.h"

/* Live/closed session counts for the relay-stats line: incremented and
 * decremented by the wrappers below, read by chat_log_relay_stats. */
static u64 g_sessions_live;
static u64 g_sessions_closed;

/* wired_wt_on_session-shaped: counts the session live for the stats line,
 * then registers it with the hub. */
void chat_on_session(
    void* ctx, wired_wt_session* s, wired_span path, wired_span protocol) {
  g_sessions_live++;
  wired_moqt_on_session(ctx, s, path, protocol);
}

/* wired_wt_on_session_close-shaped: frees the session's staging ring (its
 * views are dead with the connection) before the hub forgets the peer. */
void chat_on_session_close(void* ctx, wired_wt_session* s) {
  if (g_sessions_live) {
    g_sessions_live--;
  }
  g_sessions_closed++;
  chat_live_release(s);
  wired_moqt_on_session_close(ctx, s);
}

/* The relay-stats fields up to rel_overflow, after label. */
static usz relay_stats_head(
    char* line, usz cap, const wired_moqt_hub* hub, const char* label) {
  return wired_snprintf(
      line, cap,
      "%ssent=%llu dropped=%llu frag_dropped=%llu open_dropped=%llu reset=%llu "
      "relay_full=%llu live_sent=%llu live_dropped=%llu dg_sent=%llu "
      "dg_dropped=%llu dg_bad=%llu rel_stall=%llu rel_overflow=%llu ",
      label, (u64)hub->stat_relay_sent, (u64)hub->stat_relay_drop,
      (u64)hub->stat_frag_drop, (u64)hub->stat_open_drop,
      (u64)hub->stat_relay_reset, (u64)hub->stat_relay_full,
      (u64)hub->stat_live_sent, (u64)hub->stat_live_drop,
      (u64)hub->stat_dg_sent, (u64)hub->stat_dg_drop, (u64)hub->stat_dg_bad,
      (u64)hub->stat_rel_stall, (u64)hub->stat_rel_overflow);
}

/* The relay-stats fields from sessions on, through the newline. */
static void relay_stats_tail(char* line, usz cap, const wired_moqt_hub* hub) {
  wired_snprintf(
      line, cap,
      "sessions=%llu closed=%llu rel_wait=%llu rel_sent=%llu rel_refused=%llu "
      "rel_rings=%llu rel_in=%llu rel_fin_in=%llu rel_fin_out=%llu "
      "rel_hold=%llu rel_early=%llu\n",
      (u64)g_sessions_live, (u64)g_sessions_closed, (u64)hub->stat_rel_wait,
      (u64)hub->stat_rel_sent, (u64)hub->stat_rel_refused,
      (u64)hub->stat_rel_rings, (u64)hub->stat_rel_in_bytes,
      (u64)hub->stat_rel_fin_in, (u64)hub->stat_rel_fin_out,
      (u64)hub->stat_rel_hold, (u64)hub->stat_rel_early_return);
}

/* One line with the hub's cumulative relay outcomes, so a measurement run
 * can compare server-side drops against the receivers' own sequence gaps.
 * label is "moqt relay: " at shutdown and "moqt relay(10s): " from the
 * periodic on_step timer -- one format, so log-scraping regexes match
 * both. */
void chat_log_relay_stats(const wired_moqt_hub* hub, const char* label) {
  char line[1024]; /* label (<=17) + 24 field labels (~290 chars) + 24
                      u64s at 20 digits (480) + newline/NUL = ~790 worst
                      case; 1024 keeps headroom */
  usz at = relay_stats_head(line, sizeof line, hub, label);
  relay_stats_tail(line + at, sizeof line - at, hub);
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

void chat_goaway_setup(int argc, char** argv) {
  g_goaway_uri = wired_cliargs_str(
      argc, argv, "--goaway-uri",
      wired_envp_get(argc, argv, "WIRED_GOAWAY_URI"));
  if (!g_goaway_uri) {
    g_goaway_uri = "";
  }
  if (wired_cstr_len(g_goaway_uri) > WIRED_MOQTRUN_GOAWAY_URI_MAX) {
    wired_die("WIRED_GOAWAY_URI: longer than 8192 bytes\n");
  }
}

/* Sends GOAWAY once, at the first step after a shutdown was requested.
 * ponytail: during the drain the SDK steps (and so calls on_step) only
 * when a datagram arrives; live clients ACK and send audio, so it does. */
static void goaway_on_shutdown(wired_moqt_hub* hub) {
  static int sent;
  if (sent || !*wired_srvrun_shutdown_word()) {
    return;
  }
  sent = 1;
  wired_moqt_goaway(hub, wired_span_cstr(g_goaway_uri), GOAWAY_TIMEOUT_MS);
  wired_log_str("moqt: shutdown requested, GOAWAY sent\n");
}

/* wired_srvrun_on_step-shaped: paces the hub's live track (moqtrun.h's
 * wired_moqt_tick doc), sends GOAWAY once a shutdown starts, and emits
 * the relay-stats line every 10 seconds while sessions are live, so a
 * deployment's docker logs show whether refusals or session drops are
 * ongoing without waiting for shutdown. ctx is the hub. */
void chat_on_step(void* ctx, u64 now_ms) {
  static u64 next_ms;
  wired_moqt_tick((wired_moqt_hub*)ctx, now_ms);
  goaway_on_shutdown((wired_moqt_hub*)ctx);
  if (now_ms < next_ms) {
    return;
  }
  next_ms = now_ms + 10000;
  if (relay_stats_moved()) {
    chat_log_relay_stats((wired_moqt_hub*)ctx, "moqt relay(10s): ");
  }
}
