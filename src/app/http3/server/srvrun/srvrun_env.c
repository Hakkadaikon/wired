#include "app/http3/server/srvrun/srvrun_impl.h"
#include "app/http3/server/srvsteer/srvsteer.h"

static int srvrun_pref_wanted(
    const srvrun_cfg* cfg, const wired_srvboot_id* id);
static i64 srvrun_pref_open(
    const srvrun_cfg*       cfg,
    const wired_srvboot_id* id,
    const wired_srvrun_opt* opt);

/* Install the signal handlers wired_server_run needs: SIGTERM always,
 * SIGHUP conditionally (srvrun_install_sighup). Skipped entirely when
 * opt->no_signal_handlers is set -- e.g. a second wired_srvrun_serve_env
 * instance running alongside one that already owns the process-wide
 * handlers. */
void srvrun_install_signals(
    const srvrun_cfg* cfg, const wired_srvrun_opt* opt) {
  if (opt->no_signal_handlers) {
    return;
  }
  if (!wired_sigterm_install(srvrun_sigterm_handler)) {
    WIRED_LOG("SIGTERM install failed, no graceful shutdown\n");
  }
  srvrun_install_sighup(cfg);
}

/* Build the fixed run context from the app-facing port/id/handler/obs/opt
 * plus the mutable env this run drives -- the shared body of
 * wired_server_run_opt and wired_srvrun_serve_env. */
srvrun_cfg srvrun_build_cfg(
    wired_srvrun_env*       env,
    u16                     port,
    wired_srvboot_id*       id,
    wired_srvrun_handler    h,
    wired_srvrun_obs        obs,
    const wired_srvrun_opt* opt,
    const char*             wt_protocols) {
  return (srvrun_cfg){
      srvrun_listen(port, opt),
      id,
      h.cb,
      h.ctx,
      obs.qlog_path,
      obs.keylog_path,
      obs.cert_path,
      obs.key_path,
      obs.cc_algo,
      opt->busy_poll,
      opt->wt_on_datagram,
      opt->wt_datagram_ctx,
      opt->wt_on_stream_data,
      opt->wt_stream_data_ctx,
      opt->xdp,
      env,
      opt->no_signal_handlers,
      opt->core_id,
      wt_protocols,
      opt->wt_on_session,
      opt->wt_session_ctx,
      opt->force_retry,
      opt->wt_resource_check,
      opt->wt_resource_ctx,
      opt->wt_on_stream_reset,
      opt->wt_stream_reset_ctx,
      opt->wt_on_session_close,
      opt->wt_session_close_ctx,
      opt->on_step,
      opt->on_step_ctx,
      h.http,
      h.on_body,
      opt->wt_origin_check,
      opt->wt_origin_ctx};
}

usz wired_srvrun_env_size(void) { return sizeof(wired_srvrun_env); }

void wired_srvrun_env_init(wired_srvrun_env* env) {
  /* NOT `*env = (wired_srvrun_env){0}`: some compilers materialize that
   * compound literal as a stack temporary before copying it in, and this
   * struct is now well past a normal 8MB stack limit (WIRED_CONNTABLE_CAP
   * srvrun_conn's worth of wired_server/sdrv each) -- that pattern
   * segfaulted on overflow the moment sdrv grew past the threshold. memset
   * writes directly into *env, no intermediate stack copy. */
  bytes_memset(env, 0, sizeof(*env));
  wired_srvbigbuf_init(
      &env->bigbuf, &env->bigbuf_rows[0][0], WIRED_SRVBIGBUF_ROW_CAP);
}

/* RFC 9000 9.6.2: bind the second socket on the preferred address's port,
 * so replies on a migrated path leave FROM that port. A failed bind (or
 * XDP mode, whose rx path has no second socket) un-advertises the
 * parameter instead of promising an address that cannot answer. */
/* A preferred_address is only serviceable outside XDP mode (its rx path
 * has no second socket). */
static int srvrun_pref_wanted(
    const srvrun_cfg* cfg, const wired_srvboot_id* id) {
  return id->pref_v4 != 0 && !cfg->xdp;
}

/* The preferred-address socket: <0 un-advertises, 0 means "none needed".
 * On this run's own steered socket's port (RFC 9000 5.2) the dual-stack
 * main socket already receives that port, and a second member there would take
 * the hash fallback's share of first Initials, pinning those connections' tx_fd
 * to a socket the CID-steered rest of the connection never arrives on (every
 * later packet then reads as an old-path straggler, 9.6.2). A client migrating
 * to the preferred address is then an ordinary migration on the main socket
 * (9.6.2 / 9.3: same path validation, 8.2). Anything else opens a plain
 * socket, never the steered fd another run serves. */
static i64 srvrun_pref_open(
    const srvrun_cfg*       cfg,
    const wired_srvboot_id* id,
    const wired_srvrun_opt* opt) {
  if (!srvrun_pref_wanted(cfg, id)) {
    return -1;
  }
  if (srvsteer_fd(id->pref_v4_port, opt->core_id) == cfg->fd) {
    return 0;
  }
  return srvrun_listen_new(id->pref_v4_port, opt);
}

void srvrun_pref_listen(
    srvrun_cfg* cfg, wired_srvboot_id* id, const wired_srvrun_opt* opt) {
  i64 fd = srvrun_pref_open(cfg, id, opt);
  if (fd < 0) {
    id->pref_v4 = 0;
    return;
  }
  cfg->env->pref_fd = fd;
}
