#ifndef APP_HTTP3_SERVER_SRVLOOP_SRVLOOP_PENDING_PRIORITY_H
#define APP_HTTP3_SERVER_SRVLOOP_SRVLOOP_PENDING_PRIORITY_H

#include "app/http3/core/h3/priority.h"
#include "common/platform/sys/syscall.h"

/** RFC 9218 7.1 / 10: how many PRIORITY_UPDATE frames naming a not-yet-open
 * request stream one connection buffers (9218-010) until that stream is
 * claimed. Small and fixed: a client reprioritizing a stream ahead of
 * opening it is a corner case, not a bulk pattern, so this need not track
 * WIRED_SRVLOOP_MAX_STREAMS' own sizing. */
#define WIRED_SRVLOOP_MAX_PENDING_PRIORITY 8

/** One buffered PRIORITY_UPDATE naming a request stream this connection has
 * not opened yet (RFC 9218 10 / 9218-010). in_use == 0 marks a free slot. */
typedef struct {
  int         in_use;    /**< 0 marks a free slot */
  u64         stream_id; /**< the not-yet-open request stream id */
  h3_priority priority;  /**< the priority to apply once it opens */
} wired_srvloop_pending_priority;

#endif
