#ifndef WIRED_SRVDRIVER_SRVDRIVER_H
#define WIRED_SRVDRIVER_SRVDRIVER_H

#include "app/http3/server/srvboot/srvboot.h"
#include "app/http3/server/srvrun/srvrun.h"
#include "app/http3/server/srvthreads/srvthreads.h"
#include "app/http3/server/srvworkers/srvworkers.h"
#include "app/http3/server/srvxdp/srvxdp.h"

/** @file
 * Selects and runs one of this SDK's four server drivers (single-process,
 * multi-process fork, AF_XDP, multi-thread fan-out) from `--workers`/
 * `--ifindex`/`--cores`/`--pin-core` command-line flags, the exact same
 * exclusive-combination rules examples/word_list's driver_select hand-rolled
 * (webtransport_chat has an independent, narrower reimplementation of the
 * same idea). Only the CLI-driven decision of WHICH driver to run and its
 * dispatch are here; each driver's own knobs (wired_srvworkers_opt,
 * wired_srvxdp_cfg, wired_srvthreads_opt) are unchanged and still directly
 * usable by a caller that wants to build one by hand instead of parsing argv.
 */

/** Which of the four run paths wired_srvdriver_run takes. */
typedef enum {
  WIRED_SRVDRIVER_PLAIN = 0, /**< single-process wired_server_run_opt */
  WIRED_SRVDRIVER_WORKERS,   /**< multi-process fork, wired_srvworkers_run */
  WIRED_SRVDRIVER_XDP,       /**< AF_XDP, wired_server_run_opt + opt->xdp */
  WIRED_SRVDRIVER_THREADS,   /**< multi-thread fan-out, wired_srvthreads_run */
} wired_srvdriver_kind;

/** Resolved driver selection and its knobs, filled entirely by
 * wired_srvdriver_parse from argv (or by hand for a caller that skips CLI
 * parsing). */
typedef struct {
  wired_srvdriver_kind kind;
  u16                  port;    /**< --port (default 4433); the single source of
                                 * truth for the UDP port both wired_srvdriver_run
                                 * binds/serves on AND (XDP only) the BPF redirect
                                 * filter matches -- kept in opt instead of a
                                 * separate function argument so the two can
                                 * never drift apart and silently filter out
                                 * every real packet. */
  int pin_core;                 /**< WIRED_SRVDRIVER_PLAIN only: CPU to pin
                                 * to, -1 = off */
  wired_srvrun_opt     run;     /**< PLAIN/XDP: busy_poll and app callbacks */
  wired_srvworkers_opt workers; /**< WORKERS knobs */
  wired_srvxdp_cfg     xdp;     /**< XDP knobs (also used by THREADS+ifindex) */
  wired_srvthreads_opt threads; /**< THREADS knobs */
} wired_srvdriver_opt;

/** Parse `--port`/`--workers`/`--ifindex`/`--queue`/`--ip`/`--skb-mode`/
 * `--cores`/`--control-core`/`--pin-core` from argv into *opt, applying the
 * same exclusive-combination rules as examples/word_list's driver_select:
 * `--workers` cannot combine with `--cores` or `--ifindex`; `--pin-core`
 * cannot combine with `--workers` (use its own `--pin-cores`) or `--cores`
 * (use `--control-core`). `--ifindex` alone still composes with `--cores`
 * (AF_XDP multi-queue mode: worker i serves queue i) -- this is why XDP has
 * no dedicated flag of its own, only `--ifindex` deciding WIRED_SRVDRIVER_XDP
 * when `--cores` is absent.
 *
 * opt->port/run/workers/threads are populated only for the fields this
 * parses; a caller that also wants qlog/keylog paths, app callbacks
 * (wt_on_datagram, etc.), or cert-reload paths sets those directly on
 * opt->run and the wired_srvrun_obs it passes to wired_srvdriver_run
 * separately.
 *
 * @param argc argument count
 * @param argv argument vector
 * @param opt  destination; left untouched if an exclusive-combination
 *   conflict is detected before any field is written, but zeroed (and
 *   possibly partially filled) on a value-parse failure past that point
 *   (e.g. `--cores` present but unparseable) -- always re-check the return
 *   value, never trust opt's contents after a 0 return
 * @return 1 on success, 0 on a conflicting flag combination or a malformed
 *   value */
int wired_srvdriver_parse(int argc, char** argv, wired_srvdriver_opt* opt);

/** Dispatch to the driver selected by opt->kind, binding/serving on
 * opt->port:
 * WIRED_SRVDRIVER_PLAIN   -> wired_server_run_opt (opt->pin_core applied first)
 * WIRED_SRVDRIVER_WORKERS -> wired_srvworkers_run
 * WIRED_SRVDRIVER_XDP     -> wired_srvxdp_open + wired_server_run_opt +
 *                            wired_srvxdp_print_stats + wired_srvxdp_close
 * WIRED_SRVDRIVER_THREADS -> wired_srvthreads_run
 *
 * qlog/keylog paths in obs are passed through for PLAIN/XDP/THREADS; WORKERS
 * silently drops them (multiple forked processes writing the same qlog/
 * keylog file would interleave, matching examples/word_list's existing
 * run_workers behavior).
 *
 * @param id the fixed server identity, passed through to the selected driver
 * @param h the application's request responder
 * @param obs qlog/keylog/cert-reload paths (cert-reload is the caller's own
 *   concern via wired_certreload_load_or_selfsigned, not this function's)
 * @param opt the resolved selection from wired_srvdriver_parse (or built by
 *   hand); opt->port is the port bound/served, see wired_srvdriver_opt's doc
 * @return the selected driver's own return value (see each driver's own
 *   wired_*_run doc for its exact convention) */
int wired_srvdriver_run(
    wired_srvboot_id*          id,
    wired_srvrun_handler       h,
    wired_srvrun_obs           obs,
    const wired_srvdriver_opt* opt);

#endif
