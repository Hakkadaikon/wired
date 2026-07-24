#ifndef WIRED_H3SRV_PRIUPDATE_H
#define WIRED_H3SRV_PRIUPDATE_H

#include "common/platform/sys/syscall.h"

/* RFC 9218 7.1. Verify a received PRIORITY_UPDATE frame before it is applied:
 *   - seen on a stream other than the peer's client control stream
 *                                          -> H3_FRAME_UNEXPECTED (9218-013)
 *   - (request variant only) a Prioritized Element ID outside the
 *     client-initiated bidirectional stream id space
 *                                          -> H3_ID_ERROR (9218-014)
 * *err is left 0 and 1 is returned when the frame is acceptable. */
int wired_h3srv_priupdate_check(
    int on_control_stream, int push, u64 element_id, u16* err);

#endif
