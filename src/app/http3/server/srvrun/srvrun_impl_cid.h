#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_CID_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_CID_H

/* Internal to srvrun: migration bookkeeping -- the congestion cut-off of
 * the last path change (RFC 9000 9.4, srvrun_path_cc.c) and the connection
 * IDs this server issued (5.1.1, srvrun_own_cid.c). Not public API. */

#include "common/platform/sys/syscall.h"

/** One connection's migration bookkeeping (RFC 9000 5.1.1, 9.4). */
typedef struct {
  /** RFC 9000 9.4: the first packet number sent after the congestion
   * controller and RTT estimator were reset for a new path; ACKs and
   * losses of packets below it feed neither (0: never reset). */
  u64 cc_from_pn;
  /** The sequence numbers of the two IDs issued and not seen retired --
   * the handshake's (srvrun_conn.scid, 0) and the spare (l.spare_cid,
   * 1) -- and the next one to issue (0 until the spare is issued,
   * meaning 1). */
  u64 scid;
  u64 spare;
  u64 next;
} srvrun_mig;

#endif
