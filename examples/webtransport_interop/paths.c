/* webtransport_interop: the REQUESTS list, the session table, the /www and
 * /downloads paths, and the send-mode completion count. */

#include "wt_interop.h"

static usz cstr_len_opt(const char* s) { return s ? wired_cstr_len(s) : 0; }

/* webtransport.md: "The first component of the path identifies the
 * WebTransport endpoint" -- firefox establishes its session on the full
 * /<endpoint>/<file> URL, so everything past the first segment must be
 * dropped or file lookups build /www/<endpoint>/<file>/<file>. */
wired_span wti_endpoint_of(wired_span path) {
  wired_span p     = wired_span_strip_lead(path, '/');
  ssz        slash = wired_span_find(p, '/');
  if (slash < 0) {
    return p;
  }
  return wired_span_of(p.p, (usz)slash);
}

/* --- REQUESTS ("endpoint/file ..." list, views into the env string) ------ */

wired_span wti_endpoint;
wired_span wti_files[FILES_MAX];
usz        wti_nfiles;
u8         wti_get[FILES_MAX][GETLINE_CAP]; /* kept alive for the whole run */
usz        wti_get_len[FILES_MAX];

static void requests_add(wired_span tok) {
  ssz slash = wired_span_find(tok, '/');
  if (slash < 0 || wti_nfiles >= FILES_MAX) {
    return;
  }
  wti_endpoint = wired_span_of(tok.p, (usz)slash);
  wti_files[wti_nfiles++] =
      wired_span_of(tok.p + (usz)slash + 1, tok.n - (usz)slash - 1);
}

/* End of the space-separated token starting at i. */
static usz token_end(const char* req, usz i, usz n) {
  while (i < n && req[i] != ' ') {
    i++;
  }
  return i;
}

void wti_requests_parse(const char* req) {
  usz i = 0, n = cstr_len_opt(req);
  while (i < n) {
    usz j = token_end(req, i, n);
    if (j > i) {
      requests_add(wired_span_of((const u8*)req + i, j - i));
    }
    i = j + 1;
  }
}

void wti_prep_get_lines(void) {
  for (usz i = 0; i < wti_nfiles; i++) {
    wti_get_len[i] =
        wired_wtwire_get_put(wti_get[i], GETLINE_CAP, wti_files[i]);
  }
}

/* --- session table: connect stream id -> endpoint path ------------------- */

#define SESSIONS_MAX 8

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
  for (usz i = 0; i < SESSIONS_MAX; i++) {
    if (session_is(&g_sessions[i], sid)) {
      return &g_sessions[i];
    }
  }
  return 0;
}

static session_slot* session_alloc(void) {
  for (usz i = 0; i < SESSIONS_MAX; i++) {
    if (!g_sessions[i].used) {
      return &g_sessions[i];
    }
  }
  return &g_sessions[0]; /* table full: recycle the oldest slot */
}

void wti_session_note(const wired_wt_session* s, wired_span path) {
  session_slot* e  = session_find(s->connect_stream_id);
  wired_span    ep = wti_endpoint_of(path);
  if (!e) {
    e = session_alloc();
  }
  e->used = 1;
  e->sid  = s->connect_stream_id;
  e->len  = wired_cstr_append(e->path, sizeof e->path, 0, ep);
}

wired_span wti_session_endpoint(const wired_wt_session* s) {
  session_slot* e = session_find(s->connect_stream_id);
  if (!e) {
    return wired_span_of(0, 0);
  }
  return wired_span_of((const u8*)e->path, e->len);
}

/* --- file paths ----------------------------------------------------------- */

/* Read /www/<endpoint>/<file> into out; negative when missing/unreadable. */
ssz wti_www_read(wired_span endpoint, wired_span file, wired_mspan out) {
  char path[PATH_CAP];
  usz  at = wired_cstr_append(path, sizeof path, 0, wired_span_cstr("/www/"));
  at      = wired_cstr_append(path, sizeof path, at, endpoint);
  at      = wired_cstr_append(path, sizeof path, at, wired_span_cstr("/"));
  (void)wired_cstr_append(path, sizeof path, at, file);
  return wired_fio_read(path, out);
}

/* /downloads/<endpoint>/<name> into dest (endpoint from REQUESTS). */
void wti_dest_build(char* dest, wired_span name) {
  usz at = wired_cstr_append(dest, PATH_CAP, 0, wired_span_cstr("/downloads/"));
  at     = wired_cstr_append(dest, PATH_CAP, at, wti_endpoint);
  at     = wired_cstr_append(dest, PATH_CAP, at, wired_span_cstr("/"));
  (void)wired_cstr_append(dest, PATH_CAP, at, name);
}

/* Only the active send modes save under /downloads/<endpoint>/; creating
 * the directory in any other mode would leave residue the runner flags. */
static int mode_saves_downloads(void) {
  return wti_endpoint.n && wti_mode >= MODE_UNI_SEND;
}

void wti_setup_downloads(void) {
  char dir[PATH_CAP];
  usz  at;
  wired_fio_mkdir("/downloads");
  if (!mode_saves_downloads()) {
    return;
  }
  at = wired_cstr_append(dir, sizeof dir, 0, wired_span_cstr("/downloads/"));
  (void)wired_cstr_append(dir, sizeof dir, at, wti_endpoint);
  wired_fio_mkdir(dir);
}

/* --- send-mode completion: close the session once every file is saved ----- */

static usz g_saved; /* files fully saved under /downloads in a send mode */

/* webtransport.md leaves run termination to the endpoints: without an
 * explicit close the client idles until the runner's 60s cutoff (firefox
 * never exits; webtransport-go exits only on a much later timeout). Closing
 * the session the moment the last file landed ends the run deterministically
 * on every client. */
void wti_note_saved(wired_wt_session* s) {
  g_saved++;
  if (g_saved != wti_nfiles) {
    return;
  }
  wired_server_wt_close_session(s, 0, wired_span_of(0, 0));
  /* Reference-server behavior: the run ends by the server going away once
   * everything is saved. The graceful drain flushes the close capsule,
   * GOAWAYs, waits for the peer (bounded), and exits the process. */
  *wired_srvrun_shutdown_word() = 1;
}
