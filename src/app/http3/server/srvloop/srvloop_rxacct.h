#ifndef APP_HTTP3_SERVER_SRVLOOP_SRVLOOP_RXACCT_H
#define APP_HTTP3_SERVER_SRVLOOP_SRVLOOP_RXACCT_H

/* Included by srvloop_wt.h after the stream-table caps it sizes from. */

#include "app/http3/server/srvloop/srvloop_rxgap.h"
#include "transport/stream/flow/flow/finalsize.h"

/** RFC 9000 19.4/19.5: peer RESET_STREAM/STOP_SENDING frames one step can
 * queue. Every stream slot this loop tracks (request, WT bidi, WT uni) can
 * draw at most one RESET_STREAM and one STOP_SENDING, so two per slot holds
 * a peer tearing down everything in one packet; more than that is a flood
 * (the caller closes with H3_EXCESSIVE_LOAD on overflow). */
#define WIRED_SRVLOOP_RESET_Q                                           \
  ((usz)2 * (WIRED_SRVLOOP_MAX_STREAMS + WIRED_SRVLOOP_MAX_WT_STREAMS + \
             WIRED_SRVLOOP_MAX_WT_UNI_STREAMS))

/** One peer RESET_STREAM (is_stop 0) or STOP_SENDING (is_stop 1). */
typedef struct {
  u64 stream_id;  /**< stream id the frame named */
  u64 error_code; /**< its wire application error code */
  int is_stop;    /**< 1 for STOP_SENDING, 0 for RESET_STREAM */
} wired_srvloop_reset;

/** RFC 9000 4.1/4.5: receive accounting entries -- one per stream the peer
 * may have open at once (every request stream, every WT uni stream) plus a
 * few for the H3 plumbing and server bidi streams. */
#define WIRED_SRVLOOP_RXACCT_CAP \
  (WIRED_SRVLOOP_MAX_STREAMS + WIRED_SRVLOOP_MAX_WT_UNI_STREAMS + 8)

/** One stream's receive accounting: the highest offset the peer sent on it
 * and its final size once a FIN or RESET_STREAM fixed it (finalsize). */
typedef struct {
  int           in_use;    /**< 0 marks a free entry */
  u64           stream_id; /**< the stream this entry accounts */
  finalsize     fs;        /**< highest offset seen, final size once known */
  srvloop_rxgap gaps;      /**< holes below fs.highest (RFC 9000 21.9) */
} wired_srvloop_rxacct;

/** draft-ietf-webtrans-http3-16 5.4/5.6.2: the client WT bidi streams
 * refused for a full wt_streams[] table -- each was opened against the
 * limits of the session its signal names, and its bytes count against that
 * session's data limit once its final size is known. The caller (srvrun.c)
 * counts and clears them. */
typedef struct {
  u64 id[WIRED_SRVLOOP_MAX_STREAMS];  /**< the refused stream ids */
  u64 sid[WIRED_SRVLOOP_MAX_STREAMS]; /**< the named Session IDs (~0 when
                                         the first frame ended inside the
                                         signal) */
  u8  hdr[WIRED_SRVLOOP_MAX_STREAMS]; /**< signal bytes (0 when unknown) */
  usz n;                              /**< entries queued */
} wired_srvloop_wt_full;

#endif
