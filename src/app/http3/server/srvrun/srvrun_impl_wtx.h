#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_WTX_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_WTX_H

/* Internal to srvrun: per-connection WebTransport teardown and fairness
 * state (srvrun_conn.wtx), split out of srvrun_impl_srvrun.h. Included
 * there after SRVRUN_MAX_WT_SESSIONS and SRVRUN_WT_RESET_LATCH. */

#include "common/platform/sys/syscall.h"

typedef struct {
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
