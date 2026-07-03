#ifndef WIRED_H3SRV_PEER_H
#define WIRED_H3SRV_PEER_H

#include "app/http3/server/h3srv/state.h"
#include "common/platform/sys/syscall.h"

/* RFC 9114 6.2.1 / 7.2.4. Verify a frame seen on the peer's control stream.
 * Returns 1 and records peer SETTINGS when the first frame is SETTINGS. On a
 * violation returns 0 and sets *err to the specific connection error:
 *   - a second control stream            -> H3_STREAM_CREATION_ERROR
 * (RFC 6.2.1)
 *   - a non-SETTINGS first frame         -> H3_MISSING_SETTINGS (RFC 7.2.4)
 *   - a second SETTINGS frame            -> H3_FRAME_UNEXPECTED (RFC 7.2.4)
 * *err is left 0 on success. */
int wired_h3srv_on_peer_control(
    wired_h3srv_state *st, u64 first_frame_type, u16 *err);

/* RFC 9114 6.2 / RFC 9204 4.2. Accept a peer unidirectional stream by its type
 * (0x00 control, 0x02 QPACK encoder, 0x03 QPACK decoder). Returns 1 for any of
 * these recognised types (no connection error), 0 otherwise. */
int wired_h3srv_accept_uni(u64 stream_type);

#endif
