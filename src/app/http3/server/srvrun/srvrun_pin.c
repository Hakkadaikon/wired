#include "app/http3/server/srvrun/srvrun_impl.h"
#include "app/http3/server/srvsteer/srvsteer.h"

/* Pin id's stateless-reset secret to a per-worker copy, held in env, of the
 * start-time seed (the caller's reset_seed when set, else cert_seed): tokens
 * advertised before a certificate reload stay valid after it (RFC 9000
 * 10.3), and salting with the worker index keeps the key per worker, so
 * only the worker that issued a CID can build its reset (RFC 9000 10.3.2);
 * the salt is deterministic, so a restarted worker keeps its tokens. In
 * the fork/threads UDP modes the reuseport steering (srvsteer) routes a
 * server-issued CID to the worker with the issuing index, which is the
 * worker whose salted key can reproduce the token; without steering
 * (single worker, or srvsteer_open failed) a reset is only valid when the
 * datagram happens to reach the same-index worker -- defense in depth. */
void srvrun_pin_reset_seed(
    wired_srvrun_env* env, wired_srvboot_id* id, int worker) {
  bytes_memcpy(env->reset_seed, srvboot_reset_seed(id), sizeof env->reset_seed);
  /* mix the whole value: fork/threads indexes stay below 64, but with
   * core_id -1 a lone AF_XDP socket's identity is its full u32 queue_id */
  env->reset_seed[0] ^= (u8)worker;
  env->reset_seed[1] ^= (u8)((u32)worker >> 8);
  env->reset_seed[2] ^= (u8)((u32)worker >> 16);
  env->reset_seed[3] ^= (u8)((u32)worker >> 24);
  id->reset_seed = env->reset_seed;
}

/* The worker identity salted into the reset key: the fork/threads worker
 * index (cfg->core_id), the AF_XDP socket's own queue when no index was
 * set, or 0 for a single-process run. */
static int srvrun_reset_worker(const srvrun_cfg* cfg) {
  if (cfg->core_id >= 0) {
    return cfg->core_id;
  }
  return cfg->xdp ? (int)cfg->xdp->queue_id : 0;
}

/* No ticket/Retry seed, or a server connection ID length outside 1..20
 * (RFC 9308 9: a server SHOULD use a non-zero-length ID; RFC 9000 17.2: at
 * most 20): refuse to run. */
int srvrun_can_serve(const wired_srvboot_id* id) {
  return srvkeys_ready() && id->scid_len != 0 &&
         id->scid_len <= WIRED_MAX_CID_LEN;
}

/* opt feeds WebTransport sessions (a MoQT hub wires all three). */
static int srvrun_wt_consumer(const wired_srvrun_opt* opt) {
  return opt->wt_on_session != 0 || opt->wt_on_stream_data != 0 ||
         opt->wt_on_datagram != 0;
}

/* opt feeds WebTransport or raw-QUIC (MoQT, draft-22 6.2.2) sessions. */
static int srvrun_session_consumer(const wired_srvrun_opt* opt) {
  return srvrun_wt_consumer(opt) || opt->raw_on_session != 0;
}

/* draft-ietf-moq-transport-22/-23 6.2 (-18/-19 3.1): the QUIC DATAGRAM
 * extension (RFC 9221) MUST be negotiated on a connection carrying MOQT;
 * draft-ietf-webtrans-http3 3.1: a WebTransport server sends a non-zero
 * max_datagram_frame_size. A session-serving run whose own value is 0
 * would never advertise WebTransport (RFC 9297 2.1.1) nor carry
 * OBJECT_DATAGRAM, so it is a configuration error, not a silent default. */
static int srvrun_datagram_ok(
    const wired_srvboot_id* id, const wired_srvrun_opt* opt) {
  if (id->max_datagram_frame_size != 0 || !srvrun_session_consumer(opt)) {
    return 1;
  }
  WIRED_LOG(
      "refusing to run: session callbacks set, "
      "max_datagram_frame_size is 0\n");
  return 0;
}

/* The id is servable (srvrun_can_serve) and datagram-capable for opt's
 * session callbacks (srvrun_datagram_ok), and the run's own copy of it, of
 * obs's paths and of opt's WebTransport list is taken (srvrun_own_config);
 * opt is read only past the first check. */
static int srvrun_start_config(
    wired_srvrun_env*       env,
    wired_srvboot_id**      id,
    wired_srvrun_obs*       obs,
    const char**            wt,
    const wired_srvrun_opt* opt) {
  if (!srvrun_can_serve(*id) || !srvrun_datagram_ok(*id, opt)) {
    return 0;
  }
  *wt = opt->wt_protocols;
  return srvrun_own_config(env, id, obs, wt);
}

/* The handler and opt settings env keeps for every accept. */
static void srvrun_env_take(
    wired_srvrun_env*       env,
    wired_srvrun_handler    h,
    const wired_srvrun_opt* opt) {
  env->on_body_abort           = h.on_body_abort;
  env->wt_on_session_draining  = opt->wt_on_session_draining;
  env->wt_session_draining_ctx = opt->wt_session_draining_ctx;
  env->wt_on_stream_credit     = opt->wt_on_stream_credit;
  env->wt_stream_credit_ctx    = opt->wt_stream_credit_ctx;
  env->raw_on_session          = opt->raw_on_session;
  env->raw_session_ctx         = opt->raw_session_ctx;
  env->datagram_first          = opt->datagram_first;
  env->spin_off                = opt->spin_off;
}

/* Close the run's sockets once its loop returns: they are SO_REUSEPORT, so
 * one left open after shutdown would keep taking a share of the port's
 * packets from a later run on the same port, and nobody reads it. A
 * steered socket is the one exception -- srvsteer owns it (closing it here
 * would, in thread mode, drop it out of the live group and remap the
 * remaining workers' indices, and leave srvsteer_close to close a reused
 * fd number). */
void srvrun_close_listen(srvrun_cfg* cfg) {
  if (!srvsteer_owned(cfg->fd)) {
    wired_udp_close(cfg->fd);
  }
  if (cfg->env->pref_fd) {
    wired_udp_close(cfg->env->pref_fd);
    cfg->env->pref_fd = 0;
  }
}

int wired_srvrun_serve_env(
    wired_srvrun_env*       env,
    u16                     port,
    wired_srvboot_id*       id,
    wired_srvrun_handler    h,
    wired_srvrun_obs        obs,
    const wired_srvrun_opt* opt) {
  srvrun_cfg  cfg;
  const char* wt;
  if (!srvrun_start_config(env, &id, &obs, &wt, opt)) {
    return 0;
  }
  cfg = srvrun_build_cfg(env, port, id, h, obs, opt, wt);
  if (cfg.fd < 0) {
    return 0;
  }
  srvrun_pin_reset_seed(env, id, srvrun_reset_worker(&cfg));
  srvrun_env_take(env, h, opt);
  srvrun_pref_listen(&cfg, id, opt);
  wired_certcache_prime(&env->certcache, id);
  srvrun_install_signals(&cfg, opt);
  WIRED_LOG("listening\n");
  srvrun_loop(&cfg);
  srvrun_close_listen(&cfg);
  return 1;
}

int wired_server_run_opt(
    u16                     port,
    wired_srvboot_id*       id,
    wired_srvrun_handler    h,
    wired_srvrun_obs        obs,
    const wired_srvrun_opt* opt) {
  /* g_srvrun_env is BSS-zeroed (static storage), which happens to already
   * match wired_srvrun_env_init's own zeroing -- except bigbuf, whose
   * wired_srvbigbuf_init call points it at this env's own row storage. */
  wired_srvbigbuf_init(
      &g_srvrun_env.bigbuf, &g_srvrun_env.bigbuf_rows[0][0],
      WIRED_SRVBIGBUF_ROW_CAP);
  return wired_srvrun_serve_env(&g_srvrun_env, port, id, h, obs, opt);
}

int wired_server_run(
    u16                  port,
    wired_srvboot_id*    id,
    wired_srvrun_handler h,
    wired_srvrun_obs     obs) {
  static const wired_srvrun_opt default_opt = {
      0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0,  0, 0, 0, 0, 0};
  return wired_server_run_opt(port, id, h, obs, &default_opt);
}
