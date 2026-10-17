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

int wired_srvrun_serve_env(
    wired_srvrun_env*       env,
    u16                     port,
    wired_srvboot_id*       id,
    wired_srvrun_handler    h,
    wired_srvrun_obs        obs,
    const wired_srvrun_opt* opt) {
  srvrun_cfg cfg;
  if (!srvkeys_ready()) {
    return 0; /* no ticket/Retry seed: refuse to run */
  }
  cfg = srvrun_build_cfg(env, port, id, h, obs, opt);
  if (cfg.fd < 0) {
    return 0;
  }
  srvrun_pin_reset_seed(env, id);
  env->on_body_abort           = h.on_body_abort;
  env->wt_on_session_draining  = opt->wt_on_session_draining;
  env->wt_session_draining_ctx = opt->wt_session_draining_ctx;
  env->raw_on_session          = opt->raw_on_session;
  env->raw_session_ctx         = opt->raw_session_ctx;
  srvrun_pref_listen(&cfg, id, opt);
  wired_certcache_prime(&env->certcache, id);
  srvrun_install_signals(&cfg, opt);
  WIRED_LOG("listening\n");
  srvrun_loop(&cfg);
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
  static const wired_srvrun_opt default_opt = {0, 0,  0, 0, 0, 0, 0, 0, -1, 0,
                                               0, -1, 0, 0, 0, 0, 0, 0, 0,  0,
                                               0, 0,  0, 0, 0, 0, 0, 0, 0,  0};
  return wired_server_run_opt(port, id, h, obs, &default_opt);
}
