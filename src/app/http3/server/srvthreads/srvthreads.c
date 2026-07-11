#include "app/http3/server/srvthreads/srvthreads.h"

#include "app/http3/server/sigterm/sigterm.h"
#include "app/http3/server/srvinbox/srvinbox.h"
#include "app/http3/server/srvpin/srvpin.h"
#include "app/http3/server/srvxdpbpf/srvxdpbpf.h"
#include "common/platform/clock/clock.h"
#include "common/platform/sys/syscall.h"
#include "common/platform/thread/thread.h"

/* Phase D (tasks/loopeng/srvthreads-lifecycle/summary.md): control thread +
 * N worker threads, modeled and TLC-checked before this was written. The
 * six constraints from that summary are cited by section number at each
 * enforcement point below. */

/* mmap/munmap flags, same values as thread.c (Linux x86_64
 * <asm-generic/mman-common.h>): PROT_READ|PROT_WRITE, MAP_PRIVATE|
 * MAP_ANONYMOUS. */
#define SRVTHREADS_PROT_RW 0x3
#define SRVTHREADS_MAP_PRIVATE_ANON 0x22

/* FUTEX_WAIT, Linux <linux/futex.h>. */
#define SRVTHREADS_FUTEX_WAIT 0

/* Control's timed wait granularity: summary.md S5, "must be a timeout-armed
 * futex", not the exact value -- liveness does not depend on this number,
 * only on it being finite. */
#define SRVTHREADS_WAIT_MS 1000

/* Everything one worker thread needs, laid out in the caller's stack frame
 * (wired_srvthreads_run) so it outlives every clone()d worker without a
 * heap allocation -- the control thread only returns after every worker has
 * been joined, so the frame is guaranteed live for the whole worker
 * lifetime. */
typedef struct {
  int                     index;     /**< worker index == cores[]/queue_id */
  int                     n_total;   /**< worker count (broadcast registry) */
  wired_srvinbox_ring*    inbox_row; /**< this worker's N-ring receive row */
  wired_srvrun_env*       env;
  u16                     port;
  wired_srvboot_id        id; /**< per-worker copy (SIGHUP reload safety) */
  wired_srvrun_handler    h;
  wired_srvrun_obs        obs;
  wired_srvrun_opt        run;     /**< no_signal_handlers forced to 1 */
  const wired_srvxdp_cfg* xdp_cfg; /**< 0 in UDP mode */
  wired_srvxdpbpf*        bpf;     /**< shared BPF, XDP mode only */
} srvthreads_worker_arg;

typedef void (*srvthreads_worker_fn)(void* arg);

/* Register this worker's broadcast inbox row before serving, unregister on
 * the way out -- symmetric with wired_srvrun_broadcast_register's contract.
 * A no-op when n_total <= 1 registers too (srvrun's own broadcast path
 * collapses to the pre-Phase-E direct fan-out in that case). */
static void srvthreads_worker_serve_udp(srvthreads_worker_arg* a) {
  wired_srvrun_broadcast_register(a->index, a->n_total, a->inbox_row);
  wired_srvrun_env_init(a->env);
  wired_srvrun_serve_env(a->env, a->port, &a->id, a->h, a->obs, &a->run);
  wired_srvrun_broadcast_unregister();
}

/* XDP mode: open this worker's queue (queue_id == worker index) against the
 * shared per-interface BPF object, serve through it, then close it -- x is
 * a stack local (not heap, not the caller's frame) because it must not
 * outlive this one worker thread. A failed open leaves the worker idle
 * (summary.md's setup-failure contract: nothing this thread can retry). */
static void srvthreads_worker_serve_xdp(srvthreads_worker_arg* a) {
  wired_srvxdp     x;
  wired_srvxdp_cfg cfg = *a->xdp_cfg;
  cfg.queue_id         = (u32)a->index;
  if (wired_srvxdp_open_shared(&x, &cfg, a->bpf) < 0) return;
  a->run.xdp = &x;
  wired_srvrun_broadcast_register(a->index, a->n_total, a->inbox_row);
  wired_srvrun_env_init(a->env);
  wired_srvrun_serve_env(a->env, a->port, &a->id, a->h, a->obs, &a->run);
  wired_srvrun_broadcast_unregister();
  wired_srvxdp_close(&x);
}

/* Real worker body: pin, then dispatch to the UDP or AF_XDP serve path
 * (summary.md S1: the loop-head shutdown poll lives inside
 * wired_srvrun_serve_env/srvrun_loop already, so one of these calls is the
 * worker's entire steady-state body). */
static void srvthreads_worker_main(void* argp) {
  srvthreads_worker_arg* a = (srvthreads_worker_arg*)argp;
  wired_srvpin_bind_self(a->index);
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
static void srvthreads_worker_trampoline(void* argp) {
  g_srvthreads_worker_fn(argp);
}

/* mmap n_cores * wired_srvrun_env_size() bytes for the per-worker env table
 * in one shot. Returns 0 on failure (mmap's -errno return in -4095..-1,
 * same test as thread.c's thread_map_stack). */
static u8* srvthreads_alloc_envs(int n_cores) {
  i64 sz   = (i64)wired_srvrun_env_size() * n_cores;
  i64 base = syscall6(
      SYS_mmap, 0, sz, SRVTHREADS_PROT_RW, SRVTHREADS_MAP_PRIVATE_ANON, -1, 0);
  return base < 0 ? 0 : (u8*)base;
}

static void srvthreads_free_envs(u8* base, int n_cores) {
  syscall3(SYS_munmap, (i64)base, (i64)wired_srvrun_env_size() * n_cores, 0);
}

static wired_srvrun_env* srvthreads_env_at(u8* base, int i) {
  return (wired_srvrun_env*)(base + (usz)i * wired_srvrun_env_size());
}

/* mmap an N*N broadcast inbox mesh in one shot (Phase E): mesh[i] is worker
 * i's own receive row, fed by every worker j's wired_srvinbox_push into
 * mesh[i][j]. Sized off n_cores like srvthreads_alloc_envs, so it stays
 * proportional instead of a fixed WIRED_SRVTHREADS_MAX*MAX allocation. */
static wired_srvinbox_ring* srvthreads_alloc_mesh(int n_cores) {
  i64 sz   = (i64)sizeof(wired_srvinbox_ring) * (i64)n_cores * (i64)n_cores;
  i64 base = syscall6(
      SYS_mmap, 0, sz, SRVTHREADS_PROT_RW, SRVTHREADS_MAP_PRIVATE_ANON, -1, 0);
  if (base < 0) return 0;
  for (i64 i = 0; i < (i64)n_cores * n_cores; i++)
    wired_srvinbox_ring_init((wired_srvinbox_ring*)base + i);
  return (wired_srvinbox_ring*)base;
}

static void srvthreads_free_mesh(wired_srvinbox_ring* mesh, int n_cores) {
  syscall3(
      SYS_munmap, (i64)mesh,
      (i64)sizeof(wired_srvinbox_ring) * (i64)n_cores * (i64)n_cores, 0);
}

/* Worker i's receive row is mesh + i*n_cores (n_cores rings). */
static wired_srvinbox_ring* srvthreads_row_at(
    wired_srvinbox_ring* mesh, int i, int n_cores) {
  return mesh + (usz)i * (usz)n_cores;
}

/* Fill one worker's argument block: per-worker env pointer/index/core-scoped
 * xdp cfg, plus a deep-enough copy of id (summary.md's "each worker gets its
 * own copy" requirement -- SIGHUP reload writes id->chain/chain_count/
 * cert_seed in place, and every worker must see only its own copy). run's
 * no_signal_handlers is forced to 1: only the control thread installs
 * SIGTERM/SIGHUP (constraint 4). */
static void srvthreads_fill_arg(
    srvthreads_worker_arg*      a,
    int                         i,
    u8*                         envs,
    wired_srvinbox_ring*        mesh,
    int                         n,
    u16                         port,
    const wired_srvboot_id*     id,
    wired_srvrun_handler        h,
    wired_srvrun_obs            obs,
    const wired_srvthreads_opt* opt,
    wired_srvxdpbpf*            bpf) {
  a->index                  = i;
  a->n_total                = n;
  a->inbox_row              = srvthreads_row_at(mesh, i, n);
  a->env                    = srvthreads_env_at(envs, i);
  a->port                   = port;
  a->id                     = *id;
  a->h                      = h;
  a->obs                    = obs;
  a->run                    = opt->run;
  a->run.no_signal_handlers = 1;
  a->xdp_cfg                = opt->xdp;
  a->bpf                    = bpf;
}

/* Spawn every worker thread. On the first wired_thread_start failure, stops
 * and returns that negative error; every already-started thread is left
 * running (the caller's cleanup path still joins threads[0..i) via
 * srvthreads_join_all -- see wired_srvthreads_run). */
static i64 srvthreads_spawn_all(
    wired_thread* threads, srvthreads_worker_arg* args, int n) {
  for (int i = 0; i < n; i++) {
    i64 r =
        wired_thread_start(&threads[i], srvthreads_worker_trampoline, &args[i]);
    if (r < 0) return r;
  }
  return 0;
}

static void srvthreads_join_all(wired_thread* threads, int n) {
  for (int i = 0; i < n; i++) wired_thread_join(&threads[i]);
}

/* Control's timed wait for the shared shutdown word (constraint 5): loop a
 * FUTEX_WAIT with a fixed relative timeout until the word reads non-zero.
 * A spurious wake (EAGAIN because the word changed between the load and the
 * syscall, EINTR, or the timeout itself) all fall through to re-check the
 * word, matching the summary's "timeout is the liveness floor" argument. */
static void srvthreads_wait_shutdown(int* word) {
  quic_timespec ts = {
      SRVTHREADS_WAIT_MS / 1000, (SRVTHREADS_WAIT_MS % 1000) * 1000000};
  while (__atomic_load_n(word, __ATOMIC_ACQUIRE) == 0)
    syscall6(SYS_futex, (i64)word, SRVTHREADS_FUTEX_WAIT, 0, (i64)&ts, 0, 0);
}

/* Open the shared per-interface BPF filter in XDP mode; a no-op success (fd
 * table left zeroed, never used) in UDP mode. */
static i64 srvthreads_open_bpf(
    wired_srvxdpbpf* bpf, const wired_srvxdp_cfg* xdp) {
  if (!xdp) return 0;
  return wired_srvxdpbpf_open(bpf, xdp->ifindex, xdp->port, xdp->attach_flags);
}

static void srvthreads_close_bpf(
    wired_srvxdpbpf* bpf, const wired_srvxdp_cfg* xdp) {
  if (xdp) wired_srvxdpbpf_close(bpf);
}

/* SIGTERM/SIGHUP handler installed by the control thread only (constraint
 * 4): async-signal-safe like srvrun.c's own handler, a single RELEASE
 * store into the process-wide shutdown word every worker's srvrun_loop
 * already polls once per iteration. */
static void srvthreads_sigterm_handler(int sig) {
  (void)sig;
  __atomic_store_n(wired_srvrun_shutdown_word(), 1, __ATOMIC_RELEASE);
}

/* Block SIGTERM/SIGHUP, spawn every worker (inheriting the mask), then
 * unblock and install the handler (constraint 4: block -> spawn ->
 * unblock+install, so a signal arriving during spawn is pending and
 * delivered right after unblock). Already-started threads on a spawn
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
  if (!*envs) return 0;
  *mesh = srvthreads_alloc_mesh(n);
  if (*mesh) return 1;
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
  if (srvthreads_open_bpf(bpf, xdp) < 0) return 0;
  if (srvthreads_alloc_state(envs, mesh, n)) return 1;
  srvthreads_close_bpf(bpf, xdp);
  return 0;
}

/* Fill every worker's argument block ahead of spawning any thread. */
static void srvthreads_fill_args(
    srvthreads_worker_arg*      args,
    u8*                         envs,
    wired_srvinbox_ring*        mesh,
    int                         n,
    u16                         port,
    const wired_srvboot_id*     id,
    wired_srvrun_handler        h,
    wired_srvrun_obs            obs,
    const wired_srvthreads_opt* opt,
    wired_srvxdpbpf*            bpf) {
  for (int i = 0; i < n; i++)
    srvthreads_fill_arg(&args[i], i, envs, mesh, n, port, id, h, obs, opt, bpf);
}

/* Bind the control thread to its own core, if requested (opt->control_core
 * >= 0), before touching anything else -- pinning is cheapest to do first
 * and has no other ordering dependency. */
static void srvthreads_pin_control(int control_core) {
  if (control_core >= 0) wired_srvpin_bind_self(control_core);
}

int wired_srvthreads_run(
    u16                         port,
    wired_srvboot_id*           id,
    wired_srvrun_handler        h,
    wired_srvrun_obs            obs,
    const wired_srvthreads_opt* opt) {
  wired_thread          threads[WIRED_SRVTHREADS_MAX] = {0};
  srvthreads_worker_arg args[WIRED_SRVTHREADS_MAX];
  wired_srvxdpbpf       bpf = {-1, -1, -1};
  u8*                   envs;
  wired_srvinbox_ring*  mesh;
  int                   n = opt->n_cores;

  srvthreads_pin_control(opt->control_core);
  if (!srvthreads_setup(&bpf, &envs, &mesh, n, opt->xdp)) return 0;
  srvthreads_fill_args(args, envs, mesh, n, port, id, h, obs, opt, &bpf);

  srvthreads_start_workers(threads, args, n);
  srvthreads_wait_shutdown(wired_srvrun_shutdown_word());
  srvthreads_join_all(threads, n);

  srvthreads_close_bpf(&bpf, opt->xdp);
  srvthreads_free_mesh(mesh, n);
  srvthreads_free_envs(envs, n);
  return 1;
}
