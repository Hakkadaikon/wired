#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_LOAD_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_LOAD_H

/* Internal to srvrun: the per-connection load window (srvrun_conn.load,
 * driven by srvrun_load.c), split out of srvrun_impl_srvrun.h for the
 * Halstead file cap. */

#include "common/platform/sys/syscall.h"

/* RFC 9000 21.9: net 1-RTT packets that made no progress (no stream byte
 * never received before, no DATAGRAM payload, no ACK of our application
 * data; srvrun_noprog_note) one connection may send inside one
 * SRVRUN_RESET_WINDOW_MS window before it is closed with H3_EXCESSIVE_LOAD.
 * A legitimate peer sends a handful per second (a keepalive PING, a PTO
 * probe, a NEW_CONNECTION_ID); a duplicate or reordered ACK is netted
 * against the productive packets around it. 500/s is 50x that headroom,
 * while a flood that costs the server a decrypt and an ACK per packet runs
 * at tens of thousands. */
#define SRVRUN_MAX_NOPROG_PER_WINDOW 500

/** The fixed window the rapid-reset (RFC 9114 10.5) and no-progress (RFC
 * 9000 21.9) limits share; srvrun_roll_reset_window starts a new one. */
typedef struct {
  /** Monotonic ms the current SRVRUN_RESET_WINDOW_MS window began. */
  u64 window_start_ms;
  /** Packets without progress this window, net of productive ones. */
  u32 noprog;
} srvrun_load;

#endif
