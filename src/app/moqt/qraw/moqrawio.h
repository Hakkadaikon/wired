#ifndef MOQRAWIO_H
#define MOQRAWIO_H

#include "app/moqt/run/moqtrun.h"
#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * One wired_moqt_io table that serves both MoQT transports, so the hub
 * never branches on transport for I/O. The only per-transport step is the
 * stream-opening prefix: a WebTransport session's stream begins with the WT
 * signal (bidi 0x41 / uni 0x54 + session id, draft-ietf-webtrans-http3-15
 * 4.2), a raw-QUIC session's stream begins with the MoQT bytes themselves
 * (draft-ietf-moq-transport-19 3.3, -22 6.3). Every other op goes to the
 * srvrun call as is: srvrun applies the remaining binding differences
 * (reset code mapping, datagram qsid, session close shape) itself. */

/** Staging capacity for one prefixed stream-opening payload (signal +
 * payload, copied once before the open call). Sized to srvrun's per-stream
 * send staging (SRVRUN_WTSEND_BUF, 65536), the most one opening round can
 * carry anyway, and equal to the moqt_interop example's former private
 * buffer it replaces. A larger payload is refused (-1) on both
 * transports. */
#define MOQRAWIO_STAGE_BUF 65536

/** The srvrun operations the mux forwards prefixed stream opens to, as a
 * function-pointer table: the unity build links the real srvrun, so a test
 * cannot stub wired_server_* by symbol and fills this with recorders
 * instead. wired_moqraw_io fills it with the wired_server_* functions named
 * in each member's doc. */
typedef struct {
  /** wired_server_session_is_raw: 1 for a raw-QUIC session, 0 for WT. */
  int (*is_raw)(wired_wt_session* s);
  /** wired_server_wt_open_bidi_stream: open a bidi stream, keep it open. */
  i64 (*open_bidi_stream)(wired_wt_session* s, wired_span payload);
  /** wired_server_wt_open_uni: open a uni stream, send payload, FIN. */
  i64 (*open_uni)(wired_wt_session* s, wired_span payload);
  /** wired_server_wt_open_uni_stream: open a uni stream, keep it open. */
  i64 (*open_uni_stream)(wired_wt_session* s, wired_span payload);
} moqrawio_backend;

/** The transport-mux wired_moqt_io over backend be. Ops behave per
 * transport as follows (be->is_raw decides):
 * - open_bidi_stream / send_uni / open_uni_stream: WT prefixes the
 *   bidi/uni signal; raw sends the payload byte for byte.
 * - send_budget: WT returns the WT_MAX_DATA remainder (max_data -
 *   sent_data, 0 once exceeded, (usz)-1 when the peer set no limit); raw
 *   returns (usz)-1 (QUIC MAX_DATA is enforced by srvrun's own send
 *   credit; raw has no session-level credit, RFC 9000 4.1).
 * - send_uni2: 0 (unused by the relay paths).
 * - every other op: the wired_server_wt_* function of the same shape.
 * The ops carry no context argument, so be is held process-wide: the last
 * call wins, and be must outlive every use of the returned table.
 * @param be the backend; must not be 0
 * @return the filled table */
wired_moqt_io moqrawio_io(const moqrawio_backend* be);

/** moqrawio_io over the real srvrun backend: the io table an application
 * passes to wired_moqt_init so one hub serves WebTransport and raw-QUIC
 * sessions alike.
 * @return the filled table */
wired_moqt_io wired_moqraw_io(void);

#endif
