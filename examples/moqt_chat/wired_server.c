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

/* Signal prefix (<=9B) + one relay round. A stack buffer of this size is
 * safe everywhere below: wired_server_wt_* COPY any payload that fits their
 * own per-slot staging (srvrun.h), so nothing here must outlive its call. */
#define MOQT_SIG_BUF 2048

/* --- Movie track (--movie PATH) ----------------------------------------
 *
 * The file is read once at boot into g_movie, framed once into g_movie_wire
 * (SUBGROUP_HEADER + 16 KiB Objects, wired_moqt_publish_blob) and published
 * as the hub-owned "movie" track: every participant that SUBSCRIBEs to it
 * receives the framed bytes on one uni stream. 8 MiB: assets/movie.mp4 is
 * 5,065,711 bytes; a bigger file must raise this (wired_fio_read fails
 * loudly with WIRED_FIO_ETOOBIG rather than truncating). */
#define MOVIE_MAX (8u << 20)
/* Track Alias the framed bytes carry -- must match the frontend's
 * MOVIE_TRACK_ALIAS (moqtMovieClient.ts): chat aliases 0..3, audio 4..7,
 * movie 8. */
#define MOVIE_TRACK_ALIAS 8
#define MOVIE_TRACK_NAME "movie"
static u8 g_movie[MOVIE_MAX];
static u8 g_movie_wire[MOQDATA_BLOB_WIRE_CAP(MOVIE_MAX)];

/* Per-session staging for an oversized one-shot send (the movie's whole
 * framed blob, ~5 MB): wired_server_wt_open_uni holds a payload above its
 * 4096-byte staging as a VIEW until every byte is ACKed (srvrun.h), and the
 * WebTransport signal prefix -- different per session, it carries the
 * CONNECT stream id -- must sit contiguously in front of it. So each
 * session gets its own buffer here, claimed on its first oversized send and
 * released when the session closes (wt_on_session_close, the one point this
 * file learns the view is dead). Live sessions are bounded by both the
 * connection table and the hub's peer table, so the smaller of the two is
 * enough slots. A second oversized send on a session whose buffer is still
 * armed is refused: overwriting a live view would corrupt the bytes still
 * in flight. */
#define BIG_SIG_MAX 9
#define BIG_SLOTS                                                          \
  (WIRED_CONNTABLE_CAP < WIRED_MOQTRUN_MAX_SESSIONS ? WIRED_CONNTABLE_CAP \
                                                    : WIRED_MOQTRUN_MAX_SESSIONS)
typedef struct {
  wired_wt_session* s; /* owning session, 0 = free */
  u8                buf[BIG_SIG_MAX + sizeof g_movie_wire];
} big_slot;
static big_slot g_big[BIG_SLOTS];

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

/* A free big_slot (s == 0), or 0 when every one is taken -- a session that
 * already holds one is refused too (its view is still armed). */
static big_slot* big_slot_claim(wired_wt_session* s) {
  for (usz i = 0; i < BIG_SLOTS; i++)
    if (g_big[i].s == s) return 0;
  for (usz i = 0; i < BIG_SLOTS; i++)
    if (g_big[i].s == 0) return &g_big[i];
  return 0;
}

static void big_slot_release(wired_wt_session* s) {
  for (usz i = 0; i < BIG_SLOTS; i++)
    if (g_big[i].s == s) g_big[i].s = 0;
}

/* Oversized one-shot send: prefix + payload copied into the session's own
 * big_slot, handed to wired_server_wt_open_uni as a view (big_slot's doc). */
static i64 send_uni_big(wired_wt_session* s, wired_span payload) {
  big_slot* slot = big_slot_claim(s);
  if (!slot || payload.n > sizeof slot->buf - BIG_SIG_MAX) return -1;
  usz sig = wired_wtwire_signal_put(
      slot->buf, BIG_SIG_MAX, 0, s->connect_stream_id);
  if (sig == 0) return -1;
  bytes_memcpy(slot->buf + sig, payload.p, payload.n);
  i64 sid = wired_server_wt_open_uni(s, wired_span_of(slot->buf, sig + payload.n));
  if (sid >= 0) slot->s = s;
  return sid;
}

/* One-shot open+send+FIN (wired_server_wt_open_uni-shaped): used for a
 * relayed Object, which always completes in its stream's only round -- see
 * moqtrun.h's send_uni doc for why this must not go through
 * open_uni_stream + a bare stream_send(fin=1) instead. A payload past the
 * stack staging (only the movie track's framed blob) takes the big_slot
 * path. */
static i64 moqt_io_send_uni(wired_wt_session* s, wired_span payload) {
  u8  buf[MOQT_SIG_BUF];
  usz sig = wired_wtwire_signal_put(buf, sizeof buf, 0, s->connect_stream_id);
  if (sig == 0) return -1;
  if (payload.n > sizeof buf - sig) return send_uni_big(s, payload);
  for (usz i = 0; i < payload.n; i++) buf[sig + i] = payload.p[i];
  return wired_server_wt_open_uni(s, wired_span_of(buf, sig + payload.n));
}

/* wired_wt_on_session_close-shaped: frees the session's big_slot (its
 * view is dead with the connection) before the hub forgets the peer. */
static void on_session_close(void* ctx, wired_wt_session* s) {
  big_slot_release(s);
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
  u8  buf[MOQT_SIG_BUF];
  usz sig = wired_wtwire_signal_put(buf, sizeof buf, 0, s->connect_stream_id);
  if (sig == 0 || payload.n > sizeof buf - sig) return -1;
  for (usz i = 0; i < payload.n; i++) buf[sig + i] = payload.p[i];
  return wired_server_wt_open_uni_stream(s, wired_span_of(buf, sig + payload.n));
}

static const wired_moqt_io g_moqt_io = {
    moqt_io_open_bidi_stream,
    wired_server_wt_stream_send,
    moqt_io_send_uni,
    moqt_io_open_uni_stream,
    wired_server_wt_stream_fin,
    wired_server_wt_stream_reset,
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
  char line[192];
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
  line[n++] = '\n';
  line[n]   = 0;
  wired_log_str(line);
}

/* --movie PATH: read the file and publish it as the hub's "movie" track
 * (the movie-track block near the top of this file). No flag, no track. */
static void publish_movie(const char* path) {
  if (!path) return;
  ssz n = wired_fio_read(path, wired_mspan_of(g_movie, sizeof g_movie));
  if (n <= 0) wired_die("--movie: cannot read the file (or > MOVIE_MAX)\n");
  usz wl = wired_moqt_publish_blob(
      &g_hub, wired_span_of((const u8*)MOVIE_TRACK_NAME, sizeof MOVIE_TRACK_NAME - 1),
      MOVIE_TRACK_ALIAS, wired_span_of(g_movie, (usz)n),
      wired_mspan_of(g_movie_wire, sizeof g_movie_wire));
  if (wl == 0) wired_die("--movie: framing failed\n");
  char line[96];
  usz  ln = 0;
  append_cstr(line, &ln, "movie track: ");
  ln += dec_u64(line + ln, (u64)n);
  append_cstr(line, &ln, " bytes, framed ");
  ln += dec_u64(line + ln, (u64)wl);
  append_cstr(line, &ln, " bytes\n");
  line[ln] = 0;
  wired_log_str(line);
}

static void load_san_ipv4(int argc, char** argv, u8 san_ipv4[4], int* have_it) {
  const char* ip_str = wired_cliargs_str(argc, argv, "--san-ipv4", 0);
  *have_it           = ip_str != 0;
  if (ip_str && !wired_cliargs_ipv4(ip_str, san_ipv4))
    wired_die("--san-ipv4: expected dotted-quad a.b.c.d\n");
}

__attribute__((force_align_arg_pointer, used)) int wired_main(
    int argc, char** argv) {
  wired_srvboot_id     id = {0};
  server_keys          keys;
  wired_srvdriver_opt  opt;
  int                  have_san_ipv4;
  u64                  now_secs = wired_clock_epoch_secs();
  wired_srvrun_handler h        = {app_on_request, 0};
  wired_srvrun_obs     obs      = {
      wired_cliargs_str(argc, argv, "--qlog", 0),
      wired_cliargs_str(argc, argv, "--keylog", 0), 0, 0, 0};

  load_san_ipv4(argc, argv, keys.san_ipv4, &have_san_ipv4);
  server_identity(&id, &keys, have_san_ipv4, now_secs);
  log_cert_fingerprint(&id);

  wired_moqt_init(&g_hub, g_moqt_io);
  publish_movie(wired_cliargs_str(argc, argv, "--movie", 0));

  if (!wired_srvdriver_parse(argc, argv, &opt))
    wired_die(
        "bad CLI flags (moqt_chat is single-process only: do not pass "
        "--workers/--cores/--ifindex)\n");
  opt.run.incoming_cpu      = -1;
  opt.run.wt_on_session     = wired_moqt_on_session;
  opt.run.wt_session_ctx    = &g_hub;
  opt.run.wt_on_stream_data = wired_moqt_on_stream_data;
  opt.run.wt_stream_data_ctx = &g_hub;
  /* Without this, a session ended server-side (idle timeout after a network
   * drop, CONNECT stream close, ...) leaks its hub peer slot forever, and a
   * reconnecting client whose new session reuses the same slot memory is
   * mistaken for the dead peer -- it never receives SETUP again. */
  opt.run.wt_on_session_close  = on_session_close;
  opt.run.wt_session_close_ctx = &g_hub;

  if (!wired_srvdriver_run(&id, h, obs, &opt)) wired_die("listen failed\n");
  log_relay_stats(&g_hub);
  return 0;
}
