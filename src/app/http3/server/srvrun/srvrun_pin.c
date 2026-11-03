#include "app/http3/server/srvrun/srvrun_impl.h"

/* Pin id's stateless-reset secret to a copy of its current cert_seed held
 * in env, unless the caller already set one: tokens advertised before a
 * certificate reload stay valid after it (RFC 9000 10.3). */
void srvrun_pin_reset_seed(wired_srvrun_env* env, wired_srvboot_id* id) {
  if (id->reset_seed) {
    return;
  }
  bytes_memcpy(env->reset_seed, id->cert_seed, sizeof env->reset_seed);
  id->reset_seed = env->reset_seed;
}

/* No ticket/Retry seed, or a server connection ID length outside 1..20
 * (RFC 9308 9: a server SHOULD use a non-zero-length ID; RFC 9000 17.2: at
 * most 20): refuse to run. */
int srvrun_can_serve(const wired_srvboot_id* id) {
  return srvkeys_ready() && id->scid_len != 0 &&
         id->scid_len <= WIRED_MAX_CID_LEN;
}

/* The id is servable (srvrun_can_serve), and the run's own copy of it, of
 * obs's paths and of opt's WebTransport list is taken (srvrun_own_config);
 * opt is read only past the first check. */
static int srvrun_start_config(
    wired_srvrun_env*       env,
    wired_srvboot_id**      id,
    wired_srvrun_obs*       obs,
    const char**            wt,
    const wired_srvrun_opt* opt) {
  if (!srvrun_can_serve(*id)) {
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
 * packets from a later run on the same port, and nobody reads it. */
static void srvrun_close_listen(srvrun_cfg* cfg) {
  wired_udp_close(cfg->fd);
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
  srvrun_pin_reset_seed(env, id);
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
