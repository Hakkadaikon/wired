#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_CID_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_CID_H

/* Internal to srvrun: migration bookkeeping -- the congestion cut-off of
 * the last path change (RFC 9000 9.4, srvrun_path_cc.c) and the connection
 * IDs this server issued (5.1.1, srvrun_own_cid.c). Not public API. */

#include "common/platform/sys/syscall.h"
#include "transport/packet/header/packet/header.h"

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

/* RFC 9000 10.2.2: a just-closed connection's scid, remembered briefly so
 * its stragglers (the peer's CONNECTION_CLOSE retransmit, a final ack) are
 * swallowed instead of answered with a stateless reset -- freeing the slot
 * instantly made them unroutable, and the reset (RFC 9000 10.3) read to
 * one peer as a transport error on a cleanly closed connection (neqo
 * aborted its whole multiconnect run over it). */
typedef struct {
  u8  scid[WIRED_MAX_CID_LEN];
  u8  len;
  u64 until_ms;
} srvrun_ghost;

/* How many freshly closed connections to remember, and for how long --
 * covers the peer's own closing period (a few RTTs to a few seconds)
 * without holding real slots. */
#define SRVRUN_GHOST_SLOTS 8
#define SRVRUN_GHOST_MS 2000

/* RFC 9000 10.3 / 21.11: stateless resets sent per second, at most --
 * plenty for a restarted server to shed its stale clients, too few to
 * abuse for reflection/amplification or for probing which connection IDs
 * have live state (RFC 9000 21.11). */
#define SRVRUN_SRESET_PER_SEC 16

#endif
