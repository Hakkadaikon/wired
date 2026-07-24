#ifndef QUIC_H3_FRAME_PERMIT_H
#define QUIC_H3_FRAME_PERMIT_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 7.2. Which frame types may appear on which stream. DATA and HEADERS
 * (7.2.1, 7.2.2) are allowed only on request or push streams; CANCEL_PUSH,
 * SETTINGS, GOAWAY and MAX_PUSH_ID are allowed only on the control stream;
 * PUSH_PROMISE (7.2.5) is allowed only on request streams. A frame seen on a
 * stream where it is not permitted is an H3_FRAME_UNEXPECTED. Unknown and
 * reserved (grease) frame types are permitted everywhere -- they are ignored.
 */

enum {
  QUIC_H3_STREAM_KIND_CONTROL = 0,
  QUIC_H3_STREAM_KIND_REQUEST = 1,
  QUIC_H3_STREAM_KIND_PUSH    = 2
};

/* Returns 1 if frame_type is permitted on a stream of stream_kind, else 0. */
int quic_h3_frame_on_stream(u64 frame_type, int stream_kind);

/* Whether a received frame_type is safe to receive at all, independent of
 * which stream it arrived on (quic_h3_frame_on_stream above answers a
 * different question -- where a sender may PUT a frame type). 0 in two
 * cases, both RFC 9114 7.2.8 / connection error H3_FRAME_UNEXPECTED:
 *  - PUSH_PROMISE (7.2.5): a SERVER-to-client frame. This SDK implements the
 *    server role only (it never sends PUSH_PROMISE, 9114-070's neighbor), so
 *    any PUSH_PROMISE this endpoint receives is always unexpected.
 *  - An HTTP/2-only reserved type (0x02, 0x06, 0x08, 0x09): HTTP/3 defines no
 *    use for these code points at all (unlike a true gap, which is
 *    unknown/grease and permitted everywhere).
 * Returns 1 if frame_type is safe to receive as-is, 0 if it must be treated
 * as H3_FRAME_UNEXPECTED. */
int quic_h3_frame_recv_ok(u64 frame_type);

#endif
