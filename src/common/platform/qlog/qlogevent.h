#ifndef WIRED_QLOG_QLOGEVENT_H
#define WIRED_QLOG_QLOGEVENT_H

#include "common/platform/sys/syscall.h"

/**
 * @file
 * Build the JSON text for one qlog event (RFC 9002 stats surfaced as
 * qlog-shaped records). This layer only formats a fixed-size C string; framing
 * and appending the record to a file is qlog.h's job (wired_qlog_append).
 *
 * Each function writes a single-line JSON object into out and returns the
 * byte count written (not NUL-terminated length; out[n] is NOT guaranteed
 * to be '\0' when n == outcap). If the fully-built record does not fit in
 * outcap, nothing is committed and 0 is returned.
 *
 * group identifies which connection a record belongs to (emitted as
 * "group_id", qlog's own cross-connection correlation field): a
 * multi-connection server appends every connection's records into ONE qlog
 * file, and without per-record attribution a multi-client run's packet and
 * metrics streams interleave indistinguishably. Callers pass a stable
 * per-connection number (srvrun uses the connection's slot index).
 */

usz wired_qlogevent_packet_sent(
    char* out, usz outcap, u64 time, u64 group, u64 pn, usz bytes);
usz wired_qlogevent_packet_received(
    char* out, usz outcap, u64 time, u64 group, u64 pn, usz bytes);
usz wired_qlogevent_packet_lost(
    char* out, usz outcap, u64 time, u64 group, u64 pn);

/**
 * state is embedded verbatim as a JSON string value with no escaping —
 * pass only a fixed internal constant (e.g. "closed", "confirmed"), never
 * data derived from the wire or the application.
 */
usz wired_qlogevent_conn_state(
    char* out, usz outcap, u64 time, u64 group, const char* state);

/**
 * Input snapshot for wired_qlogevent_metrics: RFC 9002 recovery state
 * (smoothed_rtt in microseconds, cwnd and bytes_in_flight in bytes) plus the
 * connection's cumulative WebTransport counters — appended send rounds
 * (wtsend_ok), rounds rejected while the previous round was still unACKed
 * (wtsend_busy), rounds rejected by session flow control (wtsend_flow),
 * receive-window bytes dropped on buffer overflow (wtwin_drop), and
 * STREAMS_BLOCKED frames sent after a refused server-initiated stream open
 * (streams_blocked -- RFC 9000 4.6's blocked signal, so a run's qlog shows
 * whether the peer's stream ceiling was ever the limiting factor).
 */
typedef struct {
  u64 smoothed_rtt;
  u64 cwnd;
  u64 bytes_in_flight;
  u64 wtsend_ok;
  u64 wtsend_busy;
  u64 wtsend_flow;
  u64 wtwin_drop;
  u64 streams_blocked;
} wired_qlogevent_metrics_in;

usz wired_qlogevent_metrics(
    char*                             out,
    usz                               outcap,
    u64                               time,
    u64                               group,
    const wired_qlogevent_metrics_in* m);

/**
 * Input snapshot for wired_qlogevent_stream_frame: one STREAM frame's
 * identity (RFC 9000 19.8) plus the packet number it rode on.
 */
typedef struct {
  u64 stream_id;
  u64 offset;
  u64 length;
  u64 fin; /* 0 or 1 */
  u64 pn;
} wired_qlogevent_stream_frame_in;

/**
 * name picks the event kind ("stream_frame_sent", "stream_frame_lost") and,
 * like wired_qlogevent_conn_state's state, is embedded verbatim with no
 * escaping -- pass only a fixed internal constant, never wire-derived data.
 */
usz wired_qlogevent_stream_frame(
    char*                                  out,
    usz                                    outcap,
    u64                                    time,
    u64                                    group,
    const char*                            name,
    const wired_qlogevent_stream_frame_in* f);

#endif
