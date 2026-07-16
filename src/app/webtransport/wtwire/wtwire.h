#ifndef QUIC_WTWIRE_WTWIRE_H
#define QUIC_WTWIRE_WTWIRE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * WebTransport wire-format helpers (pure functions, no state).
 *
 * Covers three small wire shapes used against the webtransport-go reference
 * implementation in the quic-interop-runner:
 *
 * - Stream signal prefix: a WebTransport stream opens with varint(0x54)
 *   (unidirectional) or varint(0x41) (bidirectional) followed by
 *   varint(session_id), where session_id is the QUIC stream ID of the
 *   Extended CONNECT stream itself (always a multiple of 4, not divided).
 * - HTTP Datagram prefix (RFC 9297 SS2.1): varint(session_id / 4), the
 *   quarter stream ID.
 * - The interop-runner line protocol: "GET <filename>" requests and
 *   "PUSH <name>\n<content>" pushes.
 */

/** Write the uni (bidi=0) / bidi (bidi=1) stream signal prefix into buf.
 * @param buf        destination
 * @param cap        capacity of buf
 * @param bidi       nonzero for a bidirectional stream (0x41), else 0x54
 * @param session_id QUIC stream ID of the Extended CONNECT stream
 * @return bytes written, or 0 if it does not fit
 */
usz quic_wtwire_signal_put(u8* buf, usz cap, int bidi, u64 session_id);

/** Write the datagram quarter-stream-ID prefix varint(session_id / 4).
 * @param buf        destination
 * @param cap        capacity of buf
 * @param session_id QUIC stream ID of the Extended CONNECT stream
 * @return bytes written, or 0 if it does not fit
 */
usz quic_wtwire_qsid_put(u8* buf, usz cap, u64 session_id);

/** Read the quarter-stream-ID varint at the head of a datagram.
 * @param dg         the datagram payload
 * @param session_id set to quarter stream ID * 4 on success
 * @return bytes consumed, or 0 if the varint is truncated/missing
 */
usz quic_wtwire_qsid_take(quic_span dg, u64* session_id);

/** Parse a "GET <filename>" line. The filename is trimmed of surrounding
 * spaces, tabs, and line endings; an empty trimmed name is an error.
 * @param line the request line (trailing newline optional)
 * @param file set to a view of the trimmed filename on success
 * @return 1 on success, 0 on failure
 */
int quic_wtwire_get_parse(quic_span line, quic_span* file);

/** Write "GET <filename>" (no trailing newline) into buf.
 * @param buf      destination
 * @param cap      capacity of buf
 * @param filename the requested file name
 * @return bytes written, or 0 if it does not fit
 */
usz quic_wtwire_get_put(u8* buf, usz cap, quic_span filename);

/** Parse a "PUSH <name>\n<content>" message. The split is at the first
 * newline; the name is trimmed, and an empty trimmed name or a missing
 * newline is an error. content may be empty.
 * @param msg     the full push message
 * @param name    set to a view of the trimmed name on success
 * @param content set to a view of the bytes after the newline on success
 * @return 1 on success, 0 on failure
 */
int quic_wtwire_push_parse(quic_span msg, quic_span* name, quic_span* content);

/** Write the push header "PUSH <basename>\n" into buf.
 * @param buf      destination
 * @param cap      capacity of buf
 * @param basename the pushed file's base name
 * @return bytes written, or 0 if it does not fit
 */
usz quic_wtwire_push_head_put(u8* buf, usz cap, quic_span basename);

/** View of the path component after the last '/'; the whole path if it has
 * no '/'. A path ending in '/' yields an empty span.
 * @param path the input path
 * @return the basename view (borrows path's bytes)
 */
quic_span quic_wtwire_basename(quic_span path);

#endif
