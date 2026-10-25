#ifndef APP_HTTP3_SERVER_SRVLOOP_SRVLOOP_RXACCT_H
#define APP_HTTP3_SERVER_SRVLOOP_SRVLOOP_RXACCT_H

/* Included by srvloop_wt.h after the stream-table caps it sizes from. */

#include "transport/stream/flow/flow/finalsize.h"

/** RFC 9000 4.1/4.5: receive accounting entries -- one per stream the peer
 * may have open at once (every request stream, every WT uni stream) plus a
 * few for the H3 plumbing and server bidi streams. */
#define WIRED_SRVLOOP_RXACCT_CAP \
  (WIRED_SRVLOOP_MAX_STREAMS + WIRED_SRVLOOP_MAX_WT_UNI_STREAMS + 8)

/** One stream's receive accounting: the highest offset the peer sent on it
 * and its final size once a FIN or RESET_STREAM fixed it (finalsize). */
typedef struct {
  int       in_use;    /**< 0 marks a free entry */
  u64       stream_id; /**< the stream this entry accounts */
  finalsize fs;        /**< highest offset seen, final size once known */
} wired_srvloop_rxacct;

#endif
