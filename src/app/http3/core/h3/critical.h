#ifndef QUIC_H3_CRITICAL_H
#define QUIC_H3_CRITICAL_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 6.2. The control, QPACK encoder and QPACK decoder streams are
 * critical: closing any of them is an H3_CLOSED_CRITICAL_STREAM connection
 * error. The push stream (0x01) is not critical. */

/* 1 if stream_type names a critical unidirectional stream, else 0. */
int h3_stream_is_critical(u64 stream_type);

/* The error code to raise when a stream of stream_type is closed:
 * H3_CLOSED_CRITICAL_STREAM if critical, else 0 (no error). */
u64 h3_critical_close_error(u64 stream_type);

#endif
