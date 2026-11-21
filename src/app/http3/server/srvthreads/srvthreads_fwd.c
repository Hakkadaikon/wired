/* AF_XDP forwarding mesh for a multi-queue run (RFC 9000 9, srvxdp_fwd.c):
 * whether the run needs one, and allocating it before anything else. */

#include "app/http3/server/srvthreads/srvthreads_impl.h"

static int srvthreads_fwd_want(const wired_srvthreads_opt* opt, u8 scid_len);
static srvfwd_ring* srvthreads_fwd_open(
    const wired_srvthreads_opt* opt, u8 scid_len);

/* AF_XDP with 2+ workers needs the forwarding mesh that lets a connection
 * whose packets moved to another rx queue keep working (RFC 9000 9,
 * srvxdp_fwd.c) -- when its CIDs can carry the owner at all: shorter than
 * NCID_ROUTE_MIN_LEN, ncid_route_encode embeds nothing and decoding would
 * send short headers to a random worker (the srvsteer_size_ok rule). */
static int srvthreads_fwd_want(const wired_srvthreads_opt* opt, u8 scid_len) {
  return opt->xdp && opt->n_cores >= 2 && scid_len >= NCID_ROUTE_MIN_LEN;
}

/* Test seam (srvthreads_test_set_worker_fn precedent): substitute the
 * mesh allocation so its failure path is testable. Pass 0 to restore. */
typedef srvfwd_ring* (*srvthreads_fwd_alloc_fn)(int n_cores);
static srvthreads_fwd_alloc_fn g_srvthreads_fwd_alloc = srvthreads_alloc_fwd;

__attribute__((unused)) static void srvthreads_test_set_fwd_alloc(
    srvthreads_fwd_alloc_fn fn) {
  g_srvthreads_fwd_alloc = fn ? fn : srvthreads_alloc_fwd;
}

static srvfwd_ring* srvthreads_fwd_open(
    const wired_srvthreads_opt* opt, u8 scid_len) {
  if (!srvthreads_fwd_want(opt, scid_len)) {
    return 0;
  }
  return g_srvthreads_fwd_alloc(opt->n_cores);
}

/* The mesh, when wanted, or the run must not start: without it a worker
 * serves another queue's migrated short header and knows no connection for
 * it, so the connection stalls into its idle timeout. (The Stateless Reset
 * it answers with carries this worker's token, not the owner's --
 * srvrun_pin_reset_seed salts the key per worker -- so the peer ignores it,
 * RFC 9000 10.3.1.) */
int srvthreads_fwd_ready(
    srvfwd_ring** fwd, const wired_srvthreads_opt* opt, u8 scid_len) {
  *fwd = srvthreads_fwd_open(opt, scid_len);
  return *fwd || !srvthreads_fwd_want(opt, scid_len);
}
