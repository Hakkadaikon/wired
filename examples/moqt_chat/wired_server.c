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

#define MOQT_SIG_BUF 512 /* signal prefix (<=9B) + moqtrun's envelope */

static i64 moqt_io_open_bidi_stream(wired_wt_session* s, quic_span payload) {
  u8  buf[MOQT_SIG_BUF];
  usz sig = quic_wtwire_signal_put(buf, sizeof buf, 1, s->connect_stream_id);
  if (sig == 0 || payload.n > sizeof buf - sig) return -1;
  for (usz i = 0; i < payload.n; i++) buf[sig + i] = payload.p[i];
  return wired_server_wt_open_bidi_stream(s, quic_span_of(buf, sig + payload.n));
}

/* wired_server_wt_open_uni/stream_send hold their payload as a VIEW (srvrun.h:
 * "the caller must keep it alive and unmoved until every byte has been
 * acknowledged"), never copying it -- a stack-local buffer in this function
 * would be gone the moment the function returns, long before the SDK's pump
 * has even copied the bytes into a QUIC packet. moqtrun_relay_object (T-136)
 * can call send_uni once per active subscriber inside a single dispatch, so
 * one static buffer is not enough either -- each call needs its own slot
 * that outlives it. A fixed ring, one slot per possible peer, gives every
 * concurrent relay call an independent, sufficiently long-lived buffer. */
#define MOQT_RELAY_RING WIRED_MOQTRUN_MAX_SESSIONS
static u8  g_relay_ring[MOQT_RELAY_RING][MOQT_SIG_BUF];
static usz g_relay_ring_next;

/* One-shot open+send+FIN (wired_server_wt_open_uni-shaped): used for a
 * relayed Object, which always completes in its stream's only round -- see
 * moqtrun.h's send_uni doc for why this must not go through
 * open_uni_stream + a bare stream_send(fin=1) instead. */
static i64 moqt_io_send_uni(wired_wt_session* s, quic_span payload) {
  u8* buf = g_relay_ring[g_relay_ring_next];
  g_relay_ring_next = (g_relay_ring_next + 1) % MOQT_RELAY_RING;
  usz sig = quic_wtwire_signal_put(buf, MOQT_SIG_BUF, 0, s->connect_stream_id);
  if (sig == 0 || payload.n > MOQT_SIG_BUF - sig) return -1;
  for (usz i = 0; i < payload.n; i++) buf[sig + i] = payload.p[i];
  return wired_server_wt_open_uni(s, quic_span_of(buf, sig + payload.n));
}

static const wired_moqt_io g_moqt_io = {
    moqt_io_open_bidi_stream,
    wired_server_wt_stream_send,
    moqt_io_send_uni,
};

static wired_moqt_hub g_hub;

/* --- Plain HTTP/3 app: identical shape to examples/webtransport_echo ---- */

static int app_on_request(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    quic_obuf*                  body_out,
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
  quic_x25519_base(k->pub, k->priv);
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

static char hex_nibble(u8 v) {
  return (char)(v < 10 ? '0' + v : 'a' + (v - 10));
}

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
  quic_sha256(s.sdrv.certs[0].p, s.sdrv.certs[0].n, digest);

  {
    static const char prefix[] = "cert sha-256 fingerprint: ";
    for (; prefix[n] != 0; n++) line[n] = prefix[n];
  }
  n += hex_fingerprint(digest, line + n);
  line[n++] = '\n';
  line[n]   = 0;
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
  wired_srvboot_id     id;
  server_keys          keys;
  wired_srvdriver_opt  opt;
  int                  have_san_ipv4;
  u64                  now_secs = quic_clock_epoch_secs();
  wired_srvrun_handler h        = {app_on_request, 0};
  wired_srvrun_obs     obs      = {
      wired_cliargs_str(argc, argv, "--qlog", 0),
      wired_cliargs_str(argc, argv, "--keylog", 0), 0, 0, 0};

  load_san_ipv4(argc, argv, keys.san_ipv4, &have_san_ipv4);
  server_identity(&id, &keys, have_san_ipv4, now_secs);
  log_cert_fingerprint(&id);

  wired_moqt_init(&g_hub, g_moqt_io);

  if (!wired_srvdriver_parse(argc, argv, &opt))
    wired_die(
        "bad CLI flags (moqt_chat is single-process only: do not pass "
        "--workers/--cores/--ifindex)\n");
  opt.run.incoming_cpu      = -1;
  opt.run.wt_on_session     = wired_moqt_on_session;
  opt.run.wt_session_ctx    = &g_hub;
  opt.run.wt_on_stream_data = wired_moqt_on_stream_data;
  opt.run.wt_stream_data_ctx = &g_hub;

  if (!wired_srvdriver_run(&id, h, obs, &opt)) wired_die("listen failed\n");
  return 0;
}
