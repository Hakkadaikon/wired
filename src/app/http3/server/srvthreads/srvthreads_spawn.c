#include "app/http3/server/srvthreads/srvthreads_impl.h"

static i64 srvthreads_spawn_all(
    wired_thread* threads, srvthreads_worker_arg* args, int n);
static void srvthreads_join_all(wired_thread* threads, int n);
static void srvthreads_wait_shutdown(int* word);
static i64  srvthreads_open_bpf(
    wired_srvxdpbpf* bpf, const wired_srvxdp_cfg* xdp);
static void srvthreads_close_bpf(
    wired_srvxdpbpf* bpf, const wired_srvxdp_cfg* xdp);
static void srvthreads_sigterm_handler(int sig);
static void srvthreads_start_workers(
    wired_thread* threads, srvthreads_worker_arg* args, int n);
static int srvthreads_alloc_state(u8** envs, wired_srvinbox_ring** mesh, int n);
static int srvthreads_setup(
    wired_srvxdpbpf*        bpf,
    u8**                    envs,
    wired_srvinbox_ring**   mesh,
    int                     n,
    const wired_srvxdp_cfg* xdp);
static void srvthreads_fill_args(
    srvthreads_worker_arg*       args,
    const srvthreads_worker_arg* common,
    u8*                          envs,
    wired_srvinbox_ring*         mesh,
    int                          n,
    const int*                   cores);
static void srvthreads_pin_control(int control_core);
static void srvthreads_serve(srvthreads_worker_arg* args, int n);

/* Spawn every worker thread. On the first wired_thread_start failure, stops
 * and returns that negative error; every already-started thread is left
 * running (the caller's cleanup path still joins threads[0..i) via
 * srvthreads_join_all -- see wired_srvthreads_run). */
static i64 srvthreads_spawn_all(
    wired_thread* threads, srvthreads_worker_arg* args, int n) {
  for (int i = 0; i < n; i++) {
    i64 r =
        wired_thread_start(&threads[i], srvthreads_worker_trampoline, &args[i]);
    if (r < 0) {
      return r;
    }
  }
  return 0;
}

static void srvthreads_join_all(wired_thread* threads, int n) {
  for (int i = 0; i < n; i++) {
    wired_thread_join(&threads[i]);
  }
}

/* Control's timed wait for the shared shutdown word: loop a FUTEX_WAIT with
 * a fixed relative timeout until the word reads non-zero. A spurious wake
 * (EAGAIN because the word changed between the load and the syscall, EINTR,
 * or the timeout itself) all fall through to re-check the word -- the
 * timeout is the liveness floor, not the trigger. */
static void srvthreads_wait_shutdown(int* word) {
  timespec ts = {
      SRVTHREADS_WAIT_MS / 1000, (i64)(SRVTHREADS_WAIT_MS % 1000) * 1000000};
  while (__atomic_load_n(word, __ATOMIC_ACQUIRE) == 0) {
    wired_arch_futex(word, SRVTHREADS_FUTEX_WAIT, 0, &ts, 0, 0);
  }
}

/* Open the shared per-interface BPF filter in XDP mode; a no-op success (fd
 * table left zeroed, never used) in UDP mode. */
static i64 srvthreads_open_bpf(
    wired_srvxdpbpf* bpf, const wired_srvxdp_cfg* xdp) {
  if (!xdp) {
    return 0;
  }
  return wired_srvxdpbpf_open(bpf, xdp->ifindex, xdp->port, xdp->attach_flags);
}

static void srvthreads_close_bpf(
    wired_srvxdpbpf* bpf, const wired_srvxdp_cfg* xdp) {
  if (xdp) {
    wired_srvxdpbpf_close(bpf);
  }
}

/* SIGTERM/SIGHUP handler installed by the control thread only:
 * async-signal-safe like srvrun.c's own handler, a single RELEASE store into
 * the process-wide shutdown word every worker's srvrun_loop already polls
 * once per iteration. */
static void srvthreads_sigterm_handler(int sig) {
  (void)sig;
  __atomic_store_n(wired_srvrun_shutdown_word(), 1, __ATOMIC_RELEASE);
}

/* Block SIGTERM/SIGHUP, spawn every worker (inheriting the mask), then
 * unblock and install the handler: block -> spawn -> unblock+install, so a
 * signal arriving during spawn is pending and delivered right after
 * unblock. Already-started threads on a spawn
 * failure are the caller's problem to join/cleanup (n stays the loop bound
 * either way, since a fixed-size table was pre-zeroed). */
static void srvthreads_start_workers(
    wired_thread* threads, srvthreads_worker_arg* args, int n) {
  wired_sigmask_block_shutdown();
  srvthreads_spawn_all(threads, args, n);
  wired_sigmask_unblock_shutdown();
  wired_sigterm_install(srvthreads_sigterm_handler);
  wired_sighup_install(srvthreads_sigterm_handler);
}

/* mmap the per-worker env table and the broadcast inbox mesh; on either
 * failure, frees whichever already succeeded. */
static int srvthreads_alloc_state(
    u8** envs, wired_srvinbox_ring** mesh, int n) {
  *envs = srvthreads_alloc_envs(n);
  if (!*envs) {
    return 0;
  }
  *mesh = srvthreads_alloc_mesh(n);
  if (*mesh) {
    return 1;
  }
  srvthreads_free_envs(*envs, n);
  return 0;
}

/* Open the shared BPF filter (XDP mode) and allocate the per-worker env
 * table + broadcast mesh; any failure tears down what already succeeded and
 * returns 0. */
static int srvthreads_setup(
    wired_srvxdpbpf*        bpf,
    u8**                    envs,
    wired_srvinbox_ring**   mesh,
    int                     n,
    const wired_srvxdp_cfg* xdp) {
  if (srvthreads_open_bpf(bpf, xdp) < 0) {
    return 0;
  }
  if (srvthreads_alloc_state(envs, mesh, n)) {
    return 1;
  }
  srvthreads_close_bpf(bpf, xdp);
  return 0;
}

/* Fill every worker's argument block ahead of spawning any thread. */
static void srvthreads_fill_args(
    srvthreads_worker_arg*       args,
    const srvthreads_worker_arg* common,
    u8*                          envs,
    wired_srvinbox_ring*         mesh,
    int                          n,
    const int*                   cores) {
  for (int i = 0; i < n; i++) {
    srvthreads_fill_arg(&args[i], common, i, envs, mesh, n, cores);
  }
}

/* Bind the control thread to its own core, if requested (opt->control_core
 * >= 0), before touching anything else -- pinning is cheapest to do first
 * and has no other ordering dependency. */
static void srvthreads_pin_control(int control_core) {
  if (control_core >= 0) {
    wired_srvpin_bind_self(control_core);
  }
}

/* Spawn every worker, wait for the shutdown word, then join them all. */
static void srvthreads_serve(srvthreads_worker_arg* args, int n) {
  wired_thread threads[WIRED_SRVTHREADS_MAX] = {0};
  srvthreads_start_workers(threads, args, n);
  srvthreads_wait_shutdown(wired_srvrun_shutdown_word());
  srvthreads_join_all(threads, n);
}

int wired_srvthreads_run(
    u16                         port,
    wired_srvboot_id*           id,
    wired_srvrun_handler        h,
    wired_srvrun_obs            obs,
    const wired_srvthreads_opt* opt) {
  srvthreads_worker_arg args[WIRED_SRVTHREADS_MAX];
  srvthreads_worker_arg common;
  wired_srvxdpbpf       bpf = {-1, -1, -1, {{0, 0, 0}}};
  u8*                   envs;
  wired_srvinbox_ring*  mesh;
  int                   n = opt->n_cores;

  srvthreads_pin_control(opt->control_core);
  /* draw the ticket/Retry seeds before any worker thread can race the draw */
  if (!srvkeys_ready()) {
    return 0;
  }
  if (!srvthreads_setup(&bpf, &envs, &mesh, n, opt->xdp)) {
    return 0;
  }
  srvthreads_fill_common(&common, port, id, h, obs, opt, &bpf);
  srvthreads_fill_args(args, &common, envs, mesh, n, opt->cores);
  srvthreads_serve(args, n);

  srvthreads_close_bpf(&bpf, opt->xdp);
  srvthreads_free_mesh(mesh, n);
  srvthreads_free_envs(envs, n);
  return 1;
}
