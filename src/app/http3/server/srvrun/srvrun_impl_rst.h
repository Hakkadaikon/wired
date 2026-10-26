#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_RST_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_RST_H

/* Internal to srvrun: the control packets a connection keeps for resending
 * until ACKed (srvrun_rst.c). Not public API. */

#include "common/platform/sys/syscall.h"
#include "transport/conn/cid/peercid/peercid.h"

/** Kept resend entries the ID bookkeeping can hold at once: the owed
 * RETIRE_CONNECTION_IDs and the two NEW_CONNECTION_IDs replacing retired
 * IDs (RFC 9000 13.3). */
#define SRVRUN_CID_RETX (PEERCID_RETIRE + 2)

/* RFC 9000 13.3: one-shot control packets (stream aborts, GOAWAY) one
 * connection keeps until ACKed. Sized so every stream this connection can
 * track -- request slots, WT bidi/uni receive slots, WT send slots, both
 * CONNECT streams -- can be aborted at once, plus the GOAWAY, the owed
 * RETIRE_CONNECTION_IDs (PEERCID_RETIRE) and the two NEW_CONNECTION_IDs
 * replacing retired IDs (RFC 9000 13.3): 99 entries, about 8.7 KB per
 * connection. An entry lives about one RTT (until ACKed);
 * one that exhausts SRVRUN_PTO_MAX resends tears the connection down. */
#define SRVRUN_RST_RETX                                       \
  (WIRED_SRVLOOP_MAX_STREAMS + WIRED_SRVLOOP_MAX_WT_STREAMS + \
   WIRED_SRVLOOP_MAX_WT_UNI_STREAMS + SRVRUN_WT_SEND_SLOTS +  \
   SRVRUN_MAX_WT_SESSIONS + 1 + SRVRUN_CID_RETX)

/* Bytes one kept control packet's frames may take: the largest is a WT
 * stream abort carrying a STREAM frame with the WT header (type 1, id 8,
 * offset 1, length 1, header 2 + 8 = 21), RESET_STREAM_AT (1 + four
 * varints, the last one byte: 26) and STOP_SENDING (1 + 8 + 8 = 17): 64
 * (srvrun_wt_reset_frames); a GOAWAY STREAM frame is smaller. */
#define SRVRUN_RST_PL 64

/* One control packet awaiting its ACK: the exact frames sent, resent
 * verbatim so a final size or stream offset never changes (RFC 9000
 * 4.5/2.2). pln 0 marks a free entry; tries is the resends left. */
typedef struct {
  u8  pl[SRVRUN_RST_PL];
  u8  pln;
  u8  tries;
  u64 pn;
  u64 due_ms;
} srvrun_rst;

#endif
