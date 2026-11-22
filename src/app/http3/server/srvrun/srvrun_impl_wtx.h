#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_WTX_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_WTX_H

/* Internal to srvrun: the per-connection WebTransport session limit and
 * per-connection teardown and fairness state (srvrun_conn.wtx), split out
 * of srvrun_impl_srvrun.h. */

#include "app/http3/core/h3settings/control_settings.h"
#include "app/http3/server/srvloop/srvloop_wt.h"
#include "common/platform/sys/syscall.h"

/* draft-ietf-webtrans-http3-15 SS4 / RFC 9220 3: how many independent
 * WebTransport sessions one connection holds open (unest/est/draining, not
 * closed) at once. Build-time knob (`-DWIRED_SRVRUN_MAX_WT_SESSIONS=<n>`),
 * not WIRED_SRVLOOP_MAX_WT_STREAMS/WIRED_SRVLOOP_MAX_WT_UNI_STREAMS -- those
 * bound one connection's total reassembled WT stream slots, shared across
 * however many sessions are open, so SRVRUN_MAX_WT_SESSIONS must stay at or
 * under either (checked below); raise those with it, or n sessions split the
 * same 24/9 stream slots and SRVRUN_WT_SEND_SLOTS send slots n ways
 * (srvrun_wt_open_share_ok). Sizing: each +1 session adds one
 * wired_wt_session plus the per-session rows below (path, close message,
 * capsule queue) to every srvrun_conn -- 3600 B per connection slot on
 * x86-64 (sizeof(srvrun_conn), 2 -> 3), times WIRED_CONNTABLE_CAP of BSS. */
#ifndef WIRED_SRVRUN_MAX_WT_SESSIONS
#define WIRED_SRVRUN_MAX_WT_SESSIONS 2
#endif
#define SRVRUN_MAX_WT_SESSIONS WIRED_SRVRUN_MAX_WT_SESSIONS

/* >= 2: slots 0 and 1 keep their historical scalar names (srvrun_conn.wt/
 * wt1, wt_active/wt1_active) as an alias of the first two array entries. */
_Static_assert(SRVRUN_MAX_WT_SESSIONS >= 2, "wt/wt1 alias slots 0 and 1");

_Static_assert(
    SRVRUN_MAX_WT_SESSIONS <= WIRED_SRVLOOP_MAX_WT_STREAMS,
    "every session needs room for a bidi stream in the shared table");

_Static_assert(
    SRVRUN_MAX_WT_SESSIONS <= WIRED_SRVLOOP_MAX_WT_UNI_STREAMS,
    "every session needs room for a uni stream in the shared table");

/* Pending wired_server_wt_stream_reset entries one connection holds between
 * steps (srvrun_conn's wt_stream_reset_* latch). A full latch refuses further
 * resets (nothing is overwritten or half-applied), and the caller retries
 * after the next step drains it -- so 8 need only cover one step's realistic
 * burst, not the whole SRVRUN_WT_SEND_SLOTS table. */
#define SRVRUN_WT_RESET_LATCH 8

/* The SETTINGS_WT_INITIAL_* this server advertises (control_settings.h) are
 * promises backed by these tables: the bidi limit is the WT bidi table (a
 * server-opened stream or a second session shares it: a client stream that
 * then finds it full is refused and owed back, srvrun_wtfc_refused), the
 * uni limit fits the uni table beside an HTTP/3 client's three plumbing
 * streams, and the data limit is one receive window per stream the two
 * allow open at once. */
_Static_assert(
    H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE <= WIRED_SRVLOOP_MAX_WT_STREAMS,
    "the WT bidi table backs the advertised session stream limit");
_Static_assert(
    H3SETTINGS_WT_INIT_STREAMS_UNI_VALUE + 3 <=
        WIRED_SRVLOOP_MAX_WT_UNI_STREAMS,
    "the WT uni table backs the advertised session stream limit");
_Static_assert(
    H3SETTINGS_WT_INIT_DATA_VALUE == (H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE +
                                      H3SETTINGS_WT_INIT_STREAMS_UNI_VALUE) *
                                         (u64)WIRED_SRVLOOP_WT_BUF_CAP,
    "the advertised session data limit is the windows it may fill");

/* draft-ietf-webtrans-http3-16 5.3/5.4/5.6: one session's receive-side flow
 * control (srvrun_wtfc.c, srvrun_wtfc_grant.c). Arrays are indexed [0]
 * uni, [1] bidi. */
typedef struct {
  /** 5.6.2: client-initiated streams counted against limit, cumulative */
  u64 opened[2];
  /** WT_MAX_STREAMS in force: the SETTINGS value, then the last raise */
  u64 limit[2];
  /** client streams ended since the last raise, added by the next one */
  u64 owed[2];
  /** 5.4: Stream Body bytes of this session's streams already freed */
  u64 done;
  /** WT_MAX_DATA in force: the SETTINGS value, then the last raise */
  u64 max_data;
  /** 1 when a stream past limit closes the session (the peer sent a
   * non-zero SETTINGS_WT_INITIAL_MAX_STREAMS_*, srvrun_wtfc_open) */
  u8 streams_on;
  /** 5.1: 1 when flow control is on (the peer sent any non-zero
   * SETTINGS_WT_INITIAL_*): streams and data are counted and both limits
   * raised, the data limit enforced */
  u8 data_on;
} srvrun_wtfc;

/* draft-ietf-webtrans-http3-16 5.4: client streams refused before their
 * offer whose bytes are counted once the final size is known
 * (srvrun_wtfc_pend.c) -- as many as srvloop queues per step. */
#define SRVRUN_WTFC_PEND WIRED_SRVLOOP_MAX_STREAMS

/* One refused client stream waiting for its final size (RFC 9000 4.5). */
typedef struct {
  u64 id;   /**< the refused stream */
  u64 sid;  /**< the Session ID (CONNECT stream) it counts against */
  u8  hdr;  /**< its signal or stream-type header bytes */
  u8  used; /**< 0 marks a free entry */
} srvrun_wtfc_pend;

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
  /** #200: per session slot, the last server-initiated open refused for
   * lack of credit -- 0 none, 1 uni, 2 bidi -- and its payload length, so
   * srvrun_wt_credit_poll can tell when the same open would succeed;
   * cleared when it fires and when a session starts. */
  u8  credit_wait[SRVRUN_MAX_WT_SESSIONS];
  usz credit_len[SRVRUN_MAX_WT_SESSIONS];
  /** wtsend[] slots known free, one bit each: a set bit means in_use is 0,
   * a clear bit means "look" -- so all-zero (a fresh or reset connection)
   * is always right. Set by srvrun_wtsend_live as it finds free slots,
   * cleared by srvrun_wtsend_claim, the one place a slot becomes in use. */
  u64 send_free;
  /** 1 while no resp[] slot is in use: set by srvrun_prio_refresh at the
   * start of a pump pass, cleared by srvrun_resp_claim. 0 means "look". */
  u8 resp_idle;
  /** RFC 9218 4.1 urgency of the resp[] slot at each srvrun_conn.prio_order
   * position, filled by srvrun_prio_refresh (0 for the identity order, which
   * only stands while no response is in use). */
  u8 resp_urgency[WIRED_SRVLOOP_MAX_STREAMS];
  /** 1 while no rst[] entry awaits an ACK: set by srvrun_rst_retry when
   * its walk finds none, cleared by srvrun_rst_keep. 0 means "look". */
  u8 rst_none;
  /** Per session slot: its receive-side flow control (srvrun_wtfc). */
  srvrun_wtfc fc[SRVRUN_MAX_WT_SESSIONS];
  /** Refused client streams whose bytes are not yet counted. */
  srvrun_wtfc_pend pend[SRVRUN_WTFC_PEND];
} srvrun_wtx;

#endif
