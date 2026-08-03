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
 */

usz wired_qlogevent_packet_sent(
    char* out, usz outcap, u64 time, u64 pn, usz bytes);
usz wired_qlogevent_packet_received(
    char* out, usz outcap, u64 time, u64 pn, usz bytes);
usz wired_qlogevent_packet_lost(char* out, usz outcap, u64 time, u64 pn);

/**
 * state is embedded verbatim as a JSON string value with no escaping —
 * pass only a fixed internal constant (e.g. "closed", "confirmed"), never
 * data derived from the wire or the application.
 */
usz wired_qlogevent_conn_state(
    char* out, usz outcap, u64 time, const char* state);

/**
 * Input snapshot for wired_qlogevent_metrics: RFC 9002 recovery state
 * (smoothed_rtt in microseconds, cwnd and bytes_in_flight in bytes) plus the
 * connection's cumulative WebTransport counters — appended send rounds
 * (wtsend_ok), rounds rejected while the previous round was still unACKed
 * (wtsend_busy), rounds rejected by session flow control (wtsend_flow), and
 * receive-window bytes dropped on buffer overflow (wtwin_drop).
 */
typedef struct {
  u64 smoothed_rtt;
  u64 cwnd;
  u64 bytes_in_flight;
  u64 wtsend_ok;
  u64 wtsend_busy;
  u64 wtsend_flow;
  u64 wtwin_drop;
} wired_qlogevent_metrics_in;

usz wired_qlogevent_metrics(
    char* out, usz outcap, u64 time, const wired_qlogevent_metrics_in* m);

#endif
