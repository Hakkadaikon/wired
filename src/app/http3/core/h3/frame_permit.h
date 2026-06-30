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

#endif
