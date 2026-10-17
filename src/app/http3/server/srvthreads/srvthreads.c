/* One control thread supervises N worker threads: the control thread owns
 * signal installation and shutdown, workers own serving. */

/* mmap/munmap flags, same values as thread.c (Linux x86_64
 * <asm-generic/mman-common.h>): PROT_READ|PROT_WRITE, MAP_PRIVATE|
 * MAP_ANONYMOUS. */

/* FUTEX_WAIT, Linux <linux/futex.h>. */

/* Control's timed wait granularity must be a timeout-armed futex, not any
 * particular value -- liveness does not depend on this number, only on it
 * being finite. */

#include "app/http3/server/srvthreads/srvthreads_impl.h"

static void srvthreads_worker_serve_udp(srvthreads_worker_arg* a);
static void srvthreads_arm_xdp_run(srvthreads_worker_arg* a, wired_srvxdp* x);
static void srvthreads_worker_serve_xdp(srvthreads_worker_arg* a);
static void srvthreads_worker_main(void* argp);
__attribute__((unused)) static void srvthreads_test_set_worker_fn(
    srvthreads_worker_fn fn);
static wired_srvrun_env*    srvthreads_env_at(u8* base, int i);
static wired_srvinbox_ring* srvthreads_row_at(
    wired_srvinbox_ring* mesh, int i, int n_cores);

/* env_init first, then register (which hands out a pointer into this env) --
 * so the registry never exposes an env another thread could read mid-init.
 * Registration is unconditional, not just for n_total > 1: even a lone
 * worker (n_total == 1) must register, since it is this registration that
 * lets wired_server_broadcast_datagram find THIS worker's own env instead of
 * silently fanning out into the unused single-process g_srvrun_env. */
static void srvthreads_worker_serve_udp(srvthreads_worker_arg* a) {
  wired_srvrun_env_init(a->env);
  wired_srvrun_broadcast_register(a->index, a->n_total, a->inbox_row, a->env);
  wired_srvrun_serve_env(a->env, a->port, &a->id, a->h, a->obs, &a->run);
  wired_srvrun_broadcast_unregister();
}

/* Point a->run at the just-opened queue and this worker's own core/queue
 * index (worker i == queue i == core-routing byte i, the same 1:1 mapping
 * wired_srvxdpbpf_register relies on) -- split out from
 * srvthreads_worker_serve_xdp so the index-passing itself is directly
 * testable without a real AF_XDP queue open succeeding. */
static void srvthreads_arm_xdp_run(srvthreads_worker_arg* a, wired_srvxdp* x) {
  a->run.xdp     = x;
  a->run.core_id = a->index;
}

/* XDP mode: open this worker's queue (queue_id == worker index) against the
 * shared per-interface BPF object, serve through it, then close it -- x is
 * a stack local (not heap, not the caller's frame) because it must not
 * outlive this one worker thread. A failed open leaves the worker idle --
 * nothing this thread can retry once setup fails. */
static void srvthreads_worker_serve_xdp(srvthreads_worker_arg* a) {
  wired_srvxdp     x;
  wired_srvxdp_cfg cfg = *a->xdp_cfg;
  cfg.queue_id         = (u32)a->index;
  if (wired_srvxdp_open_shared(&x, &cfg, a->bpf) < 0) return;
  srvthreads_arm_xdp_run(a, &x);
  wired_srvrun_env_init(a->env);
  wired_srvrun_broadcast_register(a->index, a->n_total, a->inbox_row, a->env);
  wired_srvrun_serve_env(a->env, a->port, &a->id, a->h, a->obs, &a->run);
  wired_srvrun_broadcast_unregister();
  wired_srvxdp_close(&x);
}

/* Real worker body: pin to this worker's --cores entry (a->core, NOT the
 * mesh/queue index -- the parsed list was once written and never read, so
 * "--cores 1,2,3" silently pinned to CPUs 0..2), then dispatch to the UDP or
 * AF_XDP serve path -- the loop-head shutdown poll lives inside
 * wired_srvrun_serve_env/srvrun_loop already, so one of these calls is the
 * worker's entire steady-state body. */
static void srvthreads_worker_main(void* argp) {
  srvthreads_worker_arg* a = (srvthreads_worker_arg*)argp;
  wired_srvpin_bind_self(a->core);
  if (a->xdp_cfg)
    srvthreads_worker_serve_xdp(a);
  else
    srvthreads_worker_serve_udp(a);
}

/* Test-only hook (srvworkers.c's g_srvworkers_child_fn precedent): substitute
 * what a worker thread runs so lifecycle tests never bind a real socket or
 * open a real AF_XDP queue. Pass 0 to restore the real body. */
static srvthreads_worker_fn g_srvthreads_worker_fn = srvthreads_worker_main;

__attribute__((unused)) static void srvthreads_test_set_worker_fn(
    srvthreads_worker_fn fn) {
  g_srvthreads_worker_fn = fn ? fn : srvthreads_worker_main;
}

/* Trampoline so wired_thread_start's fn(void*) always dispatches through the
 * (possibly test-substituted) hook. */
void srvthreads_worker_trampoline(void* argp) { g_srvthreads_worker_fn(argp); }

/* mmap n_cores * wired_srvrun_env_size() bytes for the per-worker env table
 * in one shot. Returns 0 on failure (mmap's -errno return in -4095..-1,
 * same test as thread.c's thread_map_stack). */
u8* srvthreads_alloc_envs(int n_cores) {
  usz sz   = wired_srvrun_env_size() * (usz)n_cores;
  i64 base = wired_arch_mmap(
      0, sz, SRVTHREADS_PROT_RW, SRVTHREADS_MAP_PRIVATE_ANON, -1, 0);
  return base < 0 ? 0 : (u8*)base;
}

void srvthreads_free_envs(u8* base, int n_cores) {
  wired_arch_munmap((i64)base, wired_srvrun_env_size() * (usz)n_cores);
}

static wired_srvrun_env* srvthreads_env_at(u8* base, int i) {
  return (wired_srvrun_env*)(base + (usz)i * wired_srvrun_env_size());
}

/* mmap an N*N broadcast inbox mesh in one shot: mesh[i] is worker i's own
 * receive row, fed by every worker j's wired_srvinbox_push into
 * mesh[i][j]. Sized off n_cores like srvthreads_alloc_envs, so it stays
 * proportional instead of a fixed WIRED_SRVTHREADS_MAX*MAX allocation. */
wired_srvinbox_ring* srvthreads_alloc_mesh(int n_cores) {
  usz sz   = sizeof(wired_srvinbox_ring) * (usz)n_cores * (usz)n_cores;
  i64 base = wired_arch_mmap(
      0, sz, SRVTHREADS_PROT_RW, SRVTHREADS_MAP_PRIVATE_ANON, -1, 0);
  if (base < 0) return 0;
  for (i64 i = 0; i < (i64)n_cores * n_cores; i++)
    wired_srvinbox_ring_init((wired_srvinbox_ring*)base + i);
  return (wired_srvinbox_ring*)base;
}

void srvthreads_free_mesh(wired_srvinbox_ring* mesh, int n_cores) {
  wired_arch_munmap(
      (i64)mesh, sizeof(wired_srvinbox_ring) * (usz)n_cores * (usz)n_cores);
}

/* Worker i's receive row is mesh + i*n_cores (n_cores rings). */
static wired_srvinbox_ring* srvthreads_row_at(
    wired_srvinbox_ring* mesh, int i, int n_cores) {
  return mesh + (usz)i * (usz)n_cores;
}

/* Fill the fields every worker's argument block shares, including a
 * deep-enough copy of id -- SIGHUP reload writes id->chain/chain_count/
 * cert_seed in place, and every worker must see only its own copy. run's
 * no_signal_handlers is forced to 1: only the control thread installs
 * SIGTERM/SIGHUP. */
void srvthreads_fill_common(
    srvthreads_worker_arg*      a,
    u16                         port,
    const wired_srvboot_id*     id,
    wired_srvrun_handler        h,
    wired_srvrun_obs            obs,
    const wired_srvthreads_opt* opt,
    wired_srvxdpbpf*            bpf) {
  a->port                   = port;
  a->id                     = *id;
  a->h                      = h;
  a->obs                    = obs;
  a->run                    = opt->run;
  a->run.no_signal_handlers = 1;
  a->xdp_cfg                = opt->xdp;
  a->bpf                    = bpf;
}

/* Fill worker i's argument block: the shared fields from common, then the
 * per-worker env pointer/index/pin core/inbox row. */
void srvthreads_fill_arg(
    srvthreads_worker_arg*       a,
    const srvthreads_worker_arg* common,
    int                          i,
    u8*                          envs,
    wired_srvinbox_ring*         mesh,
    int                          n,
    const int*                   cores) {
  *a           = *common;
  a->index     = i;
  a->core      = cores[i];
  a->n_total   = n;
  a->inbox_row = srvthreads_row_at(mesh, i, n);
  a->env       = srvthreads_env_at(envs, i);
}
