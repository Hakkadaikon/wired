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

typedef struct {
  int conn_slot; /**< target connection's slot index in env->conns */
  u32 conn_gen;  /**< that slot's srvrun_conn.gen at queue time */
  usz len;       /**< bytes used at buf (qsid prefix included) */
  u8  urgency;   /**< RFC 9221 5.1: dgpriority scale, lower drains first */
  u8  sent;      /**< drained ahead of the head, awaiting its pop */
  u8  buf[SRVRUN_DGRING_SLOT];
} srvrun_dgring_entry;

#endif
