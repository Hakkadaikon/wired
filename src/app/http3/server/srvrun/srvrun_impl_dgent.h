#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_DGENT_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_DGENT_H

#include "app/datagram/dgpriority/dgpriority.h"
#include "common/platform/sys/syscall.h"

/* RFC 9297 5 / RFC 9221 5: one queued session-addressed HTTP Datagram
 * (wired_server_wt_send_datagram_to) -- the qsid prefix is already applied
 * at queue time, so buf is the complete DATAGRAM payload, addressed to the
 * connection slot it targets. The slot size leaves the qsid varint room on
 * top of the 1200-byte payload cap the single-slot broadcast queue uses. */
#define SRVRUN_DGRING_CAP 256
#define SRVRUN_DGRING_SLOT 1224
/* RFC 9002 7.7: per-packet bytes a ring DATAGRAM costs the pacer on top of
 * its payload -- short header (1 flag byte + up to a 20-byte DCID + up to a
 * 4-byte packet number, RFC 9000 17.3.1) + the 16-byte AEAD tag (RFC 9001
 * 5.3) + the DATAGRAM frame type and a 2-byte length (RFC 9221 4). */
#define SRVRUN_DG_PKT_OVERHEAD (1 + 20 + 4 + 16 + 1 + 2)

typedef struct {
  int conn_slot; /**< target connection's slot index in env->conns */
  u32 conn_gen;  /**< that slot's srvrun_conn.gen at queue time */
  usz len;       /**< bytes used at buf (qsid prefix included) */
  u8  urgency;   /**< RFC 9221 5.1: dgpriority scale, lower drains first */
  /** monotonic ms a send pass first saw it (0 = not yet), see
   * srvrun_dgring_overdue */
  u64 queued_ms;
  u8  buf[SRVRUN_DGRING_SLOT];
} srvrun_dgring_entry;

#endif
