#ifndef WIRED_SRVLOOP_WT_WATCH_H
#define WIRED_SRVLOOP_WT_WATCH_H

#include "common/platform/sys/syscall.h"

/** draft-ietf-webtrans-http3-16 6: a CONNECT stream released after the
 * peer's WT_CLOSE_SESSION, watched for "additional stream data" until the
 * peer's FIN (one at a time; srvrun arms and drains it). */
typedef struct {
  /** 1 + the watched stream id, 0 when none */
  u64 id;
  /** stream offset just past the WT_CLOSE_SESSION capsule */
  u64 end;
  /** bytes this server sent on the stream: its RESET_STREAM final size */
  u64 final;
  /** 1 once a frame carried bytes past end */
  u8 hit;
  /** 1 once the peer's FIN arrived */
  u8 fin;
} wired_srvloop_wt_watch;

#endif
