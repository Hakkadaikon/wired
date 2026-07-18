/* quic-interop-runner WebTransport server endpoint. libc-free, x86_64-linux,
 * direct syscalls, driven by the single SDK header <wired.h>.
 *
 * The runner (webtransport.md) sets TESTCASE / PROTOCOLS / REQUESTS in the
 * environment and mounts /www (files to serve), /downloads (files to save)
 * and /certs (cert.pem + priv.key). Supported test cases:
 *
 * - handshake: on session establishment, write the negotiated subprotocol
 *   to /downloads/negotiated_protocol.txt and keep serving.
 * - transfer: passive. "GET <file>" on a client uni stream is answered with
 *   "PUSH <basename>\n" + content on a NEW uni stream; on a client bidi
 *   stream with the bare content on the SAME stream; in a datagram with a
 *   "PUSH <basename>\n" + content datagram. A missing file is ignored.
 * - transfer-{unidirectional,bidirectional,datagram}-send: active. Once a
 *   session for the REQUESTS endpoint is established, every listed file is
 *   requested with "GET <file>" (new uni stream / new bidi stream / one
 *   datagram per file) and the client's replies are saved under
 *   /downloads/<endpoint>/<basename>. */

#define WIRED_MAIN /* this TU emits the libc memcpy/memset shim and _start */
#include "wired.h"

/* --- test-case modes ----------------------------------------------------- */

enum {
  MODE_HANDSHAKE,
  MODE_TRANSFER,
  MODE_UNI_SEND,
  MODE_BIDI_SEND,
  MODE_DG_SEND,
  MODE_COUNT
};

typedef struct {
  const char* name;
  int         mode;
} mode_row;

static const mode_row MODES[] = {
    {"handshake", MODE_HANDSHAKE},
    {"transfer", MODE_TRANSFER},
    {"transfer-unidirectional-send", MODE_UNI_SEND},
    {"transfer-bidirectional-send", MODE_BIDI_SEND},
    {"transfer-datagram-send", MODE_DG_SEND},
};

static int g_mode;

/* --- small pure helpers -------------------------------------------------- */

/* NUL-terminated string equality. */
static int str_eq(const char* a, const char* b) {
  usz i = 0;
  while (a[i] && a[i] == b[i]) i++;
  return a[i] == b[i];
}

static usz cstr_len_opt(const char* s) { return s ? quic_cstr_len(s) : 0; }

/* First index of c in s, or -1. */
static ssz span_find(quic_span s, u8 c) {
  for (usz i = 0; i < s.n; i++)
    if (s.p[i] == c) return (ssz)i;
  return -1;
}

static int bytes_same(const u8* a, const u8* b, usz n) {
  for (usz i = 0; i < n; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

static int span_eq(quic_span a, quic_span b) {
  return a.n == b.n && bytes_same(a.p, b.p, a.n);
}

/* Append s to dst at *at (always NUL-terminated, capped at cap-1). */
static usz cat_str(char* dst, usz cap, usz at, const char* s) {
  usz i;
  for (i = 0; s[i] && at < cap - 1; i++) dst[at++] = s[i];
  dst[at] = 0;
  return at;
}

static usz cat_span(char* dst, usz cap, usz at, quic_span s) {
  usz i;
  for (i = 0; i < s.n && at < cap - 1; i++) dst[at++] = (char)s.p[i];
  dst[at] = 0;
  return at;
}

static quic_span strip_slash(quic_span p) {
  if (p.n && p.p[0] == '/') return quic_span_of(p.p + 1, p.n - 1);
  return p;
}

/* --- REQUESTS ("endpoint/file ..." list, views into the env string) ------ */

#define FILES_MAX 200
#define GETLINE_CAP 288
/* Room for the stream signal prefix (2-byte varint type + up to 8-byte
 * varint session id) written ahead of a GET line for uni/bidi opens. */
#define GET_SIG_CAP 16

static quic_span g_endpoint; /* one endpoint (the reference peer's model) */
static quic_span g_files[FILES_MAX];
static usz       g_nfiles;
static u8        g_get[FILES_MAX][GETLINE_CAP]; /* "GET <file>" lines, kept
                                                 * alive for the whole run */
static usz g_get_len[FILES_MAX];
/* Signal-prefixed copies for stream opens, built once the session (and so
 * its id) is known; kept alive until the transfer completes. */
static u8  g_get_sig[FILES_MAX][GET_SIG_CAP + GETLINE_CAP];
static usz g_get_sig_len[FILES_MAX];

static void requests_add(quic_span tok) {
  ssz slash = span_find(tok, '/');
  if (slash < 0 || g_nfiles >= FILES_MAX) return;
  g_endpoint          = quic_span_of(tok.p, (usz)slash);
  g_files[g_nfiles++] = quic_span_of(
      tok.p + (usz)slash + 1, tok.n - (usz)slash - 1);
}

/* End of the space-separated token starting at i. */
static usz token_end(const char* req, usz i, usz n) {
  while (i < n && req[i] != ' ') i++;
  return i;
}

static void requests_parse(const char* req) {
  usz i = 0, n = cstr_len_opt(req);
  while (i < n) {
    usz j = token_end(req, i, n);
    if (j > i) requests_add(quic_span_of((const u8*)req + i, j - i));
    i = j + 1;
  }
}

static void prep_get_lines(void) {
  for (usz i = 0; i < g_nfiles; i++)
    g_get_len[i] = quic_wtwire_get_put(g_get[i], GETLINE_CAP, g_files[i]);
}

/* --- session table: connect stream id -> endpoint path ------------------- */

#define SESSIONS_MAX 8
#define PATH_CAP 320

typedef struct {
  int  used;
  u64  sid;
  usz  len;
  char path[128];
} session_slot;

static session_slot g_sessions[SESSIONS_MAX];

static int session_is(const session_slot* e, u64 sid) {
  return e->used && e->sid == sid;
}

static session_slot* session_find(u64 sid) {
  for (usz i = 0; i < SESSIONS_MAX; i++)
    if (session_is(&g_sessions[i], sid)) return &g_sessions[i];
  return 0;
}

static session_slot* session_alloc(void) {
  for (usz i = 0; i < SESSIONS_MAX; i++)
    if (!g_sessions[i].used) return &g_sessions[i];
  return &g_sessions[0]; /* table full: recycle the oldest slot */
}

static void session_note(const wired_wt_session* s, quic_span path) {
  session_slot* e  = session_find(s->connect_stream_id);
  quic_span     ep = strip_slash(path);
  if (!e) e = session_alloc();
  e->used = 1;
  e->sid  = s->connect_stream_id;
  e->len  = cat_span(e->path, sizeof e->path, 0, ep);
}

static quic_span session_endpoint(const wired_wt_session* s) {
  session_slot* e = session_find(s->connect_stream_id);
  if (!e) return quic_span_of(0, 0);
  return quic_span_of((const u8*)e->path, e->len);
}

/* --- static send buffers (view-based send APIs need stable storage) ------ */

#define POOL_SLOTS 6
#define POOL_HEAD 128
#define POOL_BODY (2u * 1024 * 1024)
#define DG_SLOTS 200
#define DG_CAP 1152

/* ponytail: round-robin, never freed -- 6 slots cover the runner's 5
 * concurrent stream transfers; grow POOL_SLOTS if a test overlaps more. */
static u8  g_pool[POOL_SLOTS][POOL_HEAD + POOL_BODY];
static usz g_pool_next;
static u8  g_dg[DG_SLOTS][DG_CAP]; /* datagram files are sub-MTU by contract */
static usz g_dg_next;

static u8* pool_take(void) {
  u8* p       = g_pool[g_pool_next];
  g_pool_next = (g_pool_next + 1) % POOL_SLOTS;
  return p;
}

static u8* dg_take(void) {
  u8* p     = g_dg[g_dg_next];
  g_dg_next = (g_dg_next + 1) % DG_SLOTS;
  return p;
}

/* --- file paths ----------------------------------------------------------- */

/* Read /www/<endpoint>/<file> into out; negative when missing/unreadable. */
static ssz www_read(quic_span endpoint, quic_span file, quic_mspan out) {
  char path[PATH_CAP];
  usz  at = cat_str(path, sizeof path, 0, "/www/");
  at      = cat_span(path, sizeof path, at, endpoint);
  at      = cat_str(path, sizeof path, at, "/");
  (void)cat_span(path, sizeof path, at, file);
  return wired_fio_read(path, out);
}

/* /downloads/<endpoint>/<name> into dest (endpoint from REQUESTS). */
static void dest_build(char* dest, quic_span name) {
  usz at = cat_str(dest, PATH_CAP, 0, "/downloads/");
  at     = cat_span(dest, PATH_CAP, at, g_endpoint);
  at     = cat_str(dest, PATH_CAP, at, "/");
  (void)cat_span(dest, PATH_CAP, at, name);
}

/* Only the active send modes save under /downloads/<endpoint>/; creating
 * the directory in any other mode would leave residue the runner flags. */
static int mode_saves_downloads(void) {
  return g_endpoint.n && g_mode >= MODE_UNI_SEND;
}

static void setup_downloads(void) {
  char dir[PATH_CAP];
  usz  at;
  wired_fio_mkdir("/downloads");
  if (!mode_saves_downloads()) return;
  at = cat_str(dir, sizeof dir, 0, "/downloads/");
  (void)cat_span(dir, sizeof dir, at, g_endpoint);
  wired_fio_mkdir(dir);
}

/* --- passive transfer: answer GETs --------------------------------------- */

/* Client uni "GET <file>": signal prefix + "PUSH <basename>\n" + content on
 * a NEW uni stream, closed after the payload (the SDK adds the FIN). */
static void serve_uni_get(wired_wt_session* s, quic_span ep, quic_span file) {
  u8* slot = pool_take();
  usz sig  = quic_wtwire_signal_put(slot, POOL_HEAD, 0, s->connect_stream_id);
  usz head = quic_wtwire_push_head_put(
      slot + sig, POOL_HEAD - sig, quic_wtwire_basename(file));
  ssz got;
  if (sig == 0 || head == 0) return;
  head += sig;
  got = www_read(ep, file, quic_mspan_of(slot + head, POOL_BODY));
  if (got < 0) return; /* missing file: ignore, keep serving */
  wired_server_wt_open_uni(s, quic_span_of(slot, head + (usz)got));
}

/* Client bidi "GET <file>": bare content back on the SAME stream. */
static void serve_bidi_get(
    wired_wt_session* s, u64 stream_id, quic_span ep, quic_span file) {
  u8* slot = pool_take();
  ssz got  = www_read(ep, file, quic_mspan_of(slot, POOL_BODY));
  if (got < 0) return;
  wired_server_wt_stream_reply(s, stream_id, quic_span_of(slot, (usz)got));
}

/* Datagram "GET <file>": one "PUSH <basename>\n" + content datagram back
 * (the SDK adds the quarter-stream-id prefix). */
static void serve_dg_get(wired_wt_session* s, quic_span ep, quic_span file) {
  u8* slot = dg_take();
  usz head =
      quic_wtwire_push_head_put(slot, DG_CAP, quic_wtwire_basename(file));
  ssz got;
  if (head == 0) return;
  got = www_read(ep, file, quic_mspan_of(slot + head, DG_CAP - head));
  if (got < 0) return;
  wired_server_wt_send_datagram_to(s, quic_span_of(slot, head + (usz)got));
}

/* --- per-stream receive state -------------------------------------------- */

enum {
  ST_FREE,      /* unused slot */
  ST_GET,       /* passive: gathering a "GET <file>" line until FIN */
  ST_PUSH_HEAD, /* uni-send: waiting for the "PUSH <name>\n" header */
  ST_PUSH_BODY, /* uni-send: appending content to /downloads */
  ST_BODY       /* bidi-send: appending the bare reply to /downloads */
};

typedef struct {
  int  state;
  u64  stream_id;
  usz  head_len;
  u8   head[512];
  char dest[PATH_CAP];
} stream_slot;

#define STREAMS_MAX 16
static stream_slot g_streams[STREAMS_MAX];

static int stream_is(const stream_slot* e, u64 id) {
  return e->state != ST_FREE && e->stream_id == id;
}

static stream_slot* stream_find(u64 id) {
  for (usz i = 0; i < STREAMS_MAX; i++)
    if (stream_is(&g_streams[i], id)) return &g_streams[i];
  return 0;
}

static stream_slot* stream_alloc(void) {
  for (usz i = 0; i < STREAMS_MAX; i++)
    if (g_streams[i].state == ST_FREE) return &g_streams[i];
  return 0;
}

/* Initial state of a stream the PEER opened, by test-case mode. Send modes
 * other than uni-send expect no peer-opened streams (bidi-send replies
 * arrive on streams this server opened, pre-registered as ST_BODY). */
static int mode_new_stream_state(void) {
  if (g_mode == MODE_TRANSFER) return ST_GET;
  return g_mode == MODE_UNI_SEND ? ST_PUSH_HEAD : ST_FREE;
}

static stream_slot* stream_open(u64 id) {
  int          st = mode_new_stream_state();
  stream_slot* e  = st == ST_FREE ? 0 : stream_alloc();
  if (!e) return 0;
  e->state     = st;
  e->stream_id = id;
  e->head_len  = 0;
  return e;
}

/* --- feeding received stream chunks, one handler per state --------------- */

static void head_append(stream_slot* e, quic_span d) {
  usz i;
  for (i = 0; i < d.n && e->head_len < sizeof e->head; i++)
    e->head[e->head_len++] = d.p[i];
}

/* Full "GET <file>" line gathered (FIN seen): answer by stream type.
 * RFC 9000 2.1: a client-initiated uni stream has id % 4 == 2. */
static void finish_get(wired_wt_session* s, stream_slot* e) {
  quic_span file;
  quic_span ep = session_endpoint(s);
  if (!quic_wtwire_get_parse(quic_span_of(e->head, e->head_len), &file))
    return;
  if ((e->stream_id & 3) == 2) serve_uni_get(s, ep, file);
  else serve_bidi_get(s, e->stream_id, ep, file);
}

static void feed_none(
    wired_wt_session* s, stream_slot* e, quic_span d, int fin) {
  (void)s;
  (void)e;
  (void)d;
  (void)fin;
}

static void feed_get(wired_wt_session* s, stream_slot* e, quic_span d, int fin) {
  head_append(e, d);
  if (fin) {
    finish_get(s, e);
    e->state = ST_FREE;
  }
}

/* Header complete: parse the name from head[0..head_n), create the download
 * file with this chunk's content bytes past the newline, keep appending. */
static void push_start(stream_slot* e, usz head_n, quic_span rest, int fin) {
  quic_span name, content;
  if (!quic_wtwire_push_parse(
          quic_span_of(e->head, head_n), &name, &content)) {
    e->state = ST_FREE;
    return;
  }
  dest_build(e->dest, quic_wtwire_basename(name));
  wired_fio_write_new(e->dest, rest);
  e->state = fin ? ST_FREE : ST_PUSH_BODY;
}

static void feed_push_head(
    wired_wt_session* s, stream_slot* e, quic_span d, int fin) {
  usz prev = e->head_len;
  ssz nl;
  usz skip;
  (void)s;
  head_append(e, d);
  nl = span_find(quic_span_of(e->head, e->head_len), '\n');
  if (nl < 0) {
    if (fin) e->state = ST_FREE; /* FIN before any newline: drop */
    return;
  }
  skip = (usz)nl + 1 - prev; /* header bytes consumed from THIS chunk */
  push_start(e, (usz)nl + 1, quic_span_of(d.p + skip, d.n - skip), fin);
}

/* ST_PUSH_BODY and ST_BODY: stream the chunk straight to the download file
 * (never buffering the whole body in RAM). */
static void feed_save(
    wired_wt_session* s, stream_slot* e, quic_span d, int fin) {
  (void)s;
  wired_fio_append(e->dest, d);
  if (fin) e->state = ST_FREE;
}

typedef void (*feed_fn)(wired_wt_session*, stream_slot*, quic_span, int);

static const feed_fn FEEDS[] = {
    feed_none,      /* ST_FREE */
    feed_get,       /* ST_GET */
    feed_push_head, /* ST_PUSH_HEAD */
    feed_save,      /* ST_PUSH_BODY */
    feed_save,      /* ST_BODY */
};

static void on_stream_data(
    void* ctx, wired_wt_session* s, u64 id, quic_span data, int fin) {
  stream_slot* e = stream_find(id);
  (void)ctx;
  if (!e) e = stream_open(id);
  if (!e) return;
  FEEDS[e->state](s, e, data, fin);
}

/* --- active send modes: issue all GETs on session establishment ---------- */

/* Build the signal-prefixed GET payloads for this session (uni/bidi opens
 * carry the WT stream signal ahead of the line; datagrams do not). */
static void prep_sig_gets(wired_wt_session* s, int bidi) {
  for (usz i = 0; i < g_nfiles; i++) {
    usz sig = quic_wtwire_signal_put(
        g_get_sig[i], GET_SIG_CAP, bidi, s->connect_stream_id);
    for (usz j = 0; j < g_get_len[i]; j++) g_get_sig[i][sig + j] = g_get[i][j];
    g_get_sig_len[i] = sig + g_get_len[i];
  }
}

static void send_gets_uni(wired_wt_session* s) {
  prep_sig_gets(s, 0);
  for (usz i = 0; i < g_nfiles; i++)
    wired_server_wt_open_uni(s, quic_span_of(g_get_sig[i], g_get_sig_len[i]));
}

/* Register the reply stream (same id) before the peer's bytes arrive, so
 * on_stream_data streams them to the right /downloads file. */
static void body_slot_open(u64 sid, quic_span file) {
  stream_slot* e = stream_alloc();
  if (!e) return;
  e->state     = ST_BODY;
  e->stream_id = sid;
  e->head_len  = 0;
  dest_build(e->dest, quic_wtwire_basename(file));
  wired_fio_write_new(e->dest, quic_span_of(0, 0));
}

static void send_gets_bidi(wired_wt_session* s) {
  prep_sig_gets(s, 1);
  for (usz i = 0; i < g_nfiles; i++) {
    i64 sid = wired_server_wt_open_bidi(
        s, quic_span_of(g_get_sig[i], g_get_sig_len[i]));
    if (sid >= 0) body_slot_open((u64)sid, g_files[i]);
  }
}

static void send_gets_dg(wired_wt_session* s) {
  for (usz i = 0; i < g_nfiles; i++)
    wired_server_wt_send_datagram_to(
        s, quic_span_of(g_get[i], g_get_len[i]));
}

typedef void (*send_fn)(wired_wt_session*);

static const send_fn SENDS[MODE_COUNT] = {
    0,              /* MODE_HANDSHAKE */
    0,              /* MODE_TRANSFER */
    send_gets_uni,  /* MODE_UNI_SEND */
    send_gets_bidi, /* MODE_BIDI_SEND */
    send_gets_dg,   /* MODE_DG_SEND */
};

static void session_send_gets(wired_wt_session* s, quic_span path) {
  if (SENDS[g_mode] && span_eq(strip_slash(path), g_endpoint))
    SENDS[g_mode](s);
}

static void on_session(
    void* ctx, wired_wt_session* s, quic_span path, quic_span protocol) {
  (void)ctx;
  session_note(s, path);
  if (g_mode == MODE_HANDSHAKE)
    wired_fio_write_new("/downloads/negotiated_protocol.txt", protocol);
  session_send_gets(s, path);
}

/* --- datagrams ------------------------------------------------------------ */

static void dg_serve(wired_wt_session* s, quic_span msg) {
  quic_span file;
  if (!quic_wtwire_get_parse(msg, &file)) return;
  serve_dg_get(s, session_endpoint(s), file);
}

/* One PUSH datagram carries a whole (sub-MTU) file. */
static void dg_save(quic_span msg) {
  quic_span name, content;
  char      dest[PATH_CAP];
  if (!quic_wtwire_push_parse(msg, &name, &content)) return;
  dest_build(dest, quic_wtwire_basename(name));
  wired_fio_write_new(dest, content);
}

static void dg_handle(wired_wt_session* s, quic_span msg) {
  if (g_mode == MODE_TRANSFER) dg_serve(s, msg);
  if (g_mode == MODE_DG_SEND) dg_save(msg);
}

static void on_datagram(void* ctx, wired_wt_session* s, quic_span dg) {
  u64 sid;
  usz used = quic_wtwire_qsid_take(dg, &sid);
  (void)ctx;
  if (!used) return;
  dg_handle(s, quic_span_of(dg.p + used, dg.n - used));
}

/* --- plain HTTP/3 app (the runner only health-checks it) ----------------- */

static int app_on_request(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    quic_obuf*                  body_out,
    const char**                content_type,
    int*                        more,
    u64*                        total_size) {
  static const u8 body[] =
      "webtransport_interop: quic-interop-runner WebTransport endpoint.\n";
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

/* --- server identity + startup ------------------------------------------- */

/* Fixed, deterministic fallback identity (same recipe as the sibling
 * examples); the interop runner always supplies a real /certs pair, loaded
 * over this via wired_certreload_load_or_selfsigned. */
static const u8 SERVER_SCID[6] = {'W', 'T', 'I', 'N', 'O', 'P'};

typedef struct {
  u8 priv[32];
  u8 pub[32];
  u8 seed[32];
  u8 rnd[32];
} server_keys;

static void server_identity(wired_srvboot_id* id, server_keys* k) {
  for (usz i = 0; i < 32; i++) {
    k->priv[i] = (u8)(0x60 + i);
    k->seed[i] = (u8)(0xa0 + i);
    k->rnd[i]  = (u8)(0xc0 + i);
  }
  quic_x25519_base(k->pub, k->priv);
  id->priv                    = k->priv;
  id->pub                     = k->pub;
  id->cert_seed               = k->seed;
  id->scid                    = SERVER_SCID;
  id->scid_len                = sizeof SERVER_SCID;
  id->random                  = k->rnd;
  id->chain                   = 0;
  id->chain_count             = 0;
  id->max_data                = 0;
  id->max_streams_bidi        = 0;
  id->max_datagram_frame_size = 65535; /* required for DATAGRAM delivery */
  id->san_ipv4                = 0;
  id->now_secs                = 0;
}

/* The certificate store backs id's views for the whole run. */
static wired_certreload_store cert_store;

static int mode_lookup(const char* tc) {
  for (usz i = 0; i < sizeof MODES / sizeof MODES[0]; i++)
    if (str_eq(tc, MODES[i].name)) return MODES[i].mode;
  return -1;
}

/* TESTCASE -> mode, or -1 when unset/unsupported. */
static int mode_of(const char* tc) { return tc ? mode_lookup(tc) : -1; }

__attribute__((force_align_arg_pointer)) int wired_main(int argc, char** argv) {
  wired_srvboot_id     id;
  server_keys          keys;
  u16                  port = (u16)wired_cliargs_int(argc, argv, "--port", 443);
  const char* cert_path     = wired_cliargs_str(argc, argv, "--cert", 0);
  const char* key_path      = wired_cliargs_str(argc, argv, "--key", "key.pem");
  wired_srvrun_handler h    = {app_on_request, 0};
  wired_srvrun_opt     opt  = {0};
  wired_srvrun_obs     obs  = {
      wired_cliargs_str(argc, argv, "--qlog-file", 0),
      wired_cliargs_str(argc, argv, "--keylog-file", 0), cert_path, key_path,
      0};

  g_mode = mode_of(wired_envp_get(argc, argv, "TESTCASE"));
  if (g_mode < 0) {
    wired_log_str("unsupported TESTCASE\n");
    return 127; /* the interop-runner code for "not supported" */
  }
  requests_parse(wired_envp_get(argc, argv, "REQUESTS"));
  prep_get_lines();
  setup_downloads();

  server_identity(&id, &keys);
  wired_certreload_load_or_selfsigned(cert_path, key_path, &cert_store, &id);

  opt.incoming_cpu      = -1;
  opt.wt_on_datagram    = on_datagram;
  opt.wt_on_stream_data = on_stream_data;
  opt.wt_on_session     = on_session;
  opt.wt_protocols      = wired_envp_get(argc, argv, "PROTOCOLS");

  if (!wired_server_run_opt(port, &id, h, obs, &opt))
    wired_die("listen failed\n");
  return 0;
}
