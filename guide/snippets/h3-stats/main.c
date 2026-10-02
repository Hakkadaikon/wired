#define WIRED_MAIN
#include "wired.h"

static usz len(const char* s) {
  usz n = 0;
  while (s[n]) n++;
  return n;
}

static int span_is(wired_span s, const char* lit) {
  usz n = len(lit);
  if (s.n != n) return 0;
  for (usz i = 0; i < n; i++)
    if (s.p[i] != (u8)lit[i]) return 0;
  return 1;
}

static int path_is(const wired_h3reqdrive_req* req, const char* p) {
  return span_is(wired_span_of(req->path, req->path_len), p);
}

static void put_str(wired_obuf* b, const char* s) {
  usz n = len(s);
  memcpy(b->p + b->len, s, n);
  b->len += n;
}

static void put_u64(wired_obuf* b, u64 v) {
  wired_fmt_u64_in in = {v, 1};
  usz              at = b->len;
  wired_fmt_u64((char*)b->p, &at, &in);
  b->len = at;
}

/* GET /stats: wired_server_wt_occupancy is a point-in-time snapshot (what is
 * open right now); wired_srvrun_env_wt_usage is the cumulative total since
 * boot. peer_streams/streams count only client-opened WT streams. */
static int on_request(void* ctx, wired_http_exchange* x) {
  wired_srvrun_env* env = (wired_srvrun_env*)ctx;
  if (!path_is(x->req, "/stats")) {
    x->status = 404;
    return 0;
  }

  wired_wt_occupancy occ = {0};
  wired_server_wt_occupancy(&occ);
  wired_srvrun_wt_usage usage = {0};
  wired_srvrun_env_wt_usage(env, &usage);

  x->body->len = 0;
  put_str(x->body, "{\"occupancy\":{\"sessions\":");
  put_u64(x->body, occ.sessions);
  put_str(x->body, ",\"sessions_cap\":");
  put_u64(x->body, occ.sessions_cap);
  put_str(x->body, ",\"peer_streams\":");
  put_u64(x->body, occ.peer_streams);
  put_str(x->body, ",\"peer_streams_cap\":");
  put_u64(x->body, occ.peer_streams_cap);
  put_str(x->body, "},\"usage\":{\"sessions\":");
  put_u64(x->body, usage.sessions);
  put_str(x->body, ",\"streams\":");
  put_u64(x->body, usage.streams);
  put_str(x->body, ",\"datagrams\":");
  put_u64(x->body, usage.datagrams);
  put_str(x->body, "}}\n");
  x->content_type = "application/json";
  return 1;
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static u8       priv[32], pub[32], seed[32], rnd[32];
  static const u8 scid[] = "guide-st";
  wired_srvboot_id id = {0};
  for (usz i = 0; i < 32; i++) {
    priv[i] = (u8)(0x50 + i);
    seed[i] = (u8)(0x90 + i);
    rnd[i]  = (u8)(0xb0 + i);
  }
  wired_x25519_base(pub, priv);
  id.priv      = priv;
  id.pub       = pub;
  id.cert_seed = seed;
  id.random    = rnd;
  id.scid      = scid;
  id.scid_len  = sizeof scid - 1; /* without the string's NUL */

  /* wired_srvrun_env_wt_usage needs an addressable env, unlike the single
   * process-wide instance wired_server_run/wired_server_run_opt drive --
   * same one-instance mmap srvthreads.c uses for its per-worker envs. */
  i64 envsz = (i64)wired_srvrun_env_size();
  i64 base  = wired_arch_mmap(0, envsz, 0x3 /* PROT_READ|PROT_WRITE */,
                              0x22 /* MAP_PRIVATE|MAP_ANONYMOUS */, -1, 0);
  if (base < 0) return 1;
  wired_srvrun_env* env = (wired_srvrun_env*)base;
  wired_srvrun_env_init(env);

  u16 port = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {.http = on_request, .ctx = env};
  wired_srvrun_obs     obs = {0};
  wired_srvrun_opt     opt = {0};
  opt.incoming_cpu = -1;
  return wired_srvrun_serve_env(env, port, &id, h, obs, &opt) ? 0 : 1;
}
