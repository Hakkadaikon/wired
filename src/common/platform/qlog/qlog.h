#ifndef WIRED_QLOG_QLOG_H
#define WIRED_QLOG_QLOG_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/**
 * @file
 * Append one qlog record to a file in JSON-SEQ framing (RFC 7464): each
 * record is bracketed by a leading RS (0x1E) and a trailing LF, so a reader
 * can resynchronize after a truncated write. This layer only frames and
 * appends an already-built JSON record; building the JSON text for a given
 * event (packet_sent, packet_received, ...) is the caller's responsibility.
 */

/**
 * Append record to path as one JSON-SEQ frame: RS + record + LF. Creates
 * path if it does not exist (wired_fio_append semantics).
 *
 * @param path NUL-terminated qlog file path
 * @param record a single JSON value's text (no surrounding RS/LF)
 * @return bytes written (== record.n + 2) on success; a negative -errno
 *         when the underlying append fails
 */
ssz wired_qlog_append(const char* path, quic_span record);

#endif
