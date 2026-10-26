#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_WTX_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_WTX_H

/* Internal to srvrun: per-connection WebTransport teardown and fairness
 * state (srvrun_conn.wtx), split out of srvrun_impl_srvrun.h. Included
 * there after SRVRUN_MAX_WT_SESSIONS. */

#include "common/platform/sys/syscall.h"

/* Pending wired_server_wt_stream_reset entries one connection holds between
 * steps (srvrun_conn's wt_stream_reset_* latch). A full latch refuses further
 * resets (nothing is overwritten or half-applied), and the caller retries
 * after the next step drains it -- so 8 need only cover one step's realistic
 * burst, not the whole SRVRUN_WT_SEND_SLOTS table. */
#define SRVRUN_WT_RESET_LATCH 8

typedef struct {
  /** draft-ietf-webtrans-http3-15 SS4.4/8.2: wired_server_wt_stream_reset
   * calls pending -- latched (not sent inline) for the same
   * no-srvrun_cfg-in-a-callback reason as wt_close_pending, drained on the
   * next srvrun_on_step (srvrun_drain_wt_stream_reset): one standard
   * RESET_STREAM (RFC 9000 19.4) per entry, carrying the app code mapped
   * through wired_wterrmap_to_http3 and the final size captured at latch
   * time (the send slot's cumulative armed bytes; captured BEFORE the slot
   * is freed, because freeing loses the count and a final size below the
   * bytes already sent is an RFC 9000 4.5 FINAL_SIZE_ERROR at the peer).
   * A bounded queue, not wt_close_pending's single slot: one connection
   * can carry several app-driven streams (a relay fans one source out to
   * many), and a second reset latched in the same step must not silently
   * overwrite the first -- the peer would wait on the unnotified stream
   * forever. No STOP_SENDING rides along: every target is a
   * server-initiated uni stream, which has no peer-to-server half to stop
   * (RFC 9000 19.5 makes STOP_SENDING on it a STREAM_STATE_ERROR). */
  u64 reset_id[SRVRUN_WT_RESET_LATCH];
  u64 reset_final[SRVRUN_WT_RESET_LATCH];
  /** Per wt_stream_reset_* latch entry: the owning session's CONNECT
   * stream id, for the RESET_STREAM_AT's header (srvrun_wt_reset_frames);
   * SRVRUN_WT_NO_SID for a STOP_SENDING entry. */
  u64 reset_sid[SRVRUN_WT_RESET_LATCH];
  /** draft-ietf-webtrans-http3-16 6: per session slot, 1 + the CONNECT
   * stream id shutdown sent WT_CLOSE_SESSION on and still waits for the
   * peer to close (srvrun_wt_close_all_live), 0 when none. */
  u64 close_wait[SRVRUN_MAX_WT_SESSIONS];
  /** draft-ietf-webtrans-http3-16 8: per session slot, the send slot its
   * next fair pass starts from (srvrun_wt_fair_keep). */
  u8 fair_next[SRVRUN_MAX_WT_SESSIONS];
} srvrun_wtx;

#endif
