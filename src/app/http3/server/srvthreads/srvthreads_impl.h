#ifndef APP_HTTP3_SERVER_SRVTHREADS_SRVTHREADS_IMPL_H
#define APP_HTTP3_SERVER_SRVTHREADS_SRVTHREADS_IMPL_H

/* Internal to the srvthreads*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/http3/server/sigterm/sigterm.h"
#include "app/http3/server/srvinbox/srvinbox.h"
#include "app/http3/server/srvkeys/srvkeys.h"
#include "app/http3/server/srvpin/srvpin.h"
#include "app/http3/server/srvthreads/srvthreads.h"
#include "app/http3/server/srvxdpbpf/srvxdpbpf.h"
#include "common/platform/clock/clock.h"
#include "common/platform/sys/syscall.h"
#include "common/platform/thread/thread.h"

#define SRVTHREADS_PROT_RW 0x3
#define SRVTHREADS_MAP_PRIVATE_ANON 0x22
#define SRVTHREADS_FUTEX_WAIT 0
#define SRVTHREADS_WAIT_MS 1000

/* Everything one worker thread needs, laid out in the caller's stack frame
 * (wired_srvthreads_run) so it outlives every clone()d worker without a
 * heap allocation -- the control thread only returns after every worker has
 * been joined, so the frame is guaranteed live for the whole worker
 * lifetime. */
typedef struct {
  wired_srvinbox_ring*    inbox_row; /**< this worker's N-ring receive row */
  wired_srvrun_env*       env;
  const wired_srvxdp_cfg* xdp_cfg; /**< 0 in UDP mode */
  wired_srvxdpbpf*        bpf;     /**< shared BPF, XDP mode only */
  wired_srvrun_handler    h;
  wired_srvrun_obs        obs;
  wired_srvboot_id        id;    /**< per-worker copy (SIGHUP reload safety) */
  wired_srvrun_opt        run;   /**< no_signal_handlers forced to 1 */
  int                     index; /**< worker index: mesh row/column and
                                  * XDP queue id (0..n_total-1) */
  int core;                      /**< CPU to pin this worker to
                                  * (opt->cores[index]) */
  int n_total;                   /**< worker count (broadcast registry) */
  u16 port;
} srvthreads_worker_arg;

typedef void (*srvthreads_worker_fn)(void* arg);

void                 srvthreads_worker_trampoline(void* argp);
u8*                  srvthreads_alloc_envs(int n_cores);
void                 srvthreads_free_envs(u8* base, int n_cores);
wired_srvinbox_ring* srvthreads_alloc_mesh(int n_cores);
void srvthreads_free_mesh(wired_srvinbox_ring* mesh, int n_cores);
void srvthreads_fill_common(
    srvthreads_worker_arg*      a,
    u16                         port,
    const wired_srvboot_id*     id,
    wired_srvrun_handler        h,
    wired_srvrun_obs            obs,
    const wired_srvthreads_opt* opt,
    wired_srvxdpbpf*            bpf);
void srvthreads_fill_arg(
    srvthreads_worker_arg*       a,
    const srvthreads_worker_arg* common,
    int                          i,
    u8*                          envs,
    wired_srvinbox_ring*         mesh,
    int                          n,
    const int*                   cores);

#endif
