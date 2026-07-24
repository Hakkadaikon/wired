#ifndef WIRED_SRVLOOP_PRIORITY_CTRL_H
#define WIRED_SRVLOOP_PRIORITY_CTRL_H

#include "app/http3/server/srvloop/srvloop.h"
#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * RFC 9218 7.1 / 10 / RFC 9114 6.2.1: reassemble the peer's control stream
 * (past its leading 0x00 type varint) into `l->ctrl` and walk every complete
 * HTTP/3 frame landed there, applying each PRIORITY_UPDATE (9218-013/9218-010,
 * via wired_srvloop_priority_apply) and skipping every other frame type
 * (SETTINGS/GOAWAY/... are not this file's concern). A validation failure
 * (9218-013's wrong-stream case cannot occur here by construction -- this is
 * only ever called with a control-stream frame -- but 9218-014's bad element
 * id can) latches l->priupdate_violation instead of applying anything. */

/** RFC 9000 2.1/2.2: if the walked frame at `frame` (of `type`) is a STREAM
 * frame on the peer's client uni control stream (RFC 9114 6.2.1: leading
 * type varint 0x00), land its post-type-varint bytes into l->ctrl and walk
 * any newly complete frame(s). Returns 1 iff this frame belonged to the
 * control stream (whether or not it decoded to a control-relevant frame),
 * mirroring this file's sibling gather_* functions in dispatch.c.
 * @param l the loop whose ctrl buffer / streams[] / pending_priority[] to
 *   update
 * @param type the walked frame's type
 * @param frame the walked frame's own bytes (header + body) */
int wired_srvloop_ctrl_gather(wired_srvloop* l, u64 type, quic_span frame);

/** RFC 9218 7.1 / 9218-013: if the walked frame at `frame` (of `type`) is a
 * client bidi (request) STREAM frame whose data begins with a PRIORITY_UPDATE
 * frame, latch l->priupdate_violation = H3_FRAME_UNEXPECTED -- the frame MUST
 * only be sent on the client's control stream. Returns 1 iff this frame
 * belonged to a request stream at all (whether or not it carried a
 * violation).
 * @param l the loop whose priupdate_violation to latch
 * @param type the walked frame's type
 * @param frame the walked frame's own bytes (header + body) */
int wired_srvloop_req_priupdate_gather(
    wired_srvloop* l, u64 type, quic_span frame);

#endif
