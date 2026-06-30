#ifndef QUIC_H3CONN_ESTABLISH_H
#define QUIC_H3CONN_ESTABLISH_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 6.2 / 7.2.4. Open the local HTTP/3 control stream: the
 * unidirectional stream type 0x00 followed by a SETTINGS frame. Returns 1 with
 * *out_len set, 0 if out lacks capacity. */
int quic_h3conn_open_control(u8 *out, usz cap, usz *out_len);

/* RFC 9114 6.2 / 7.2.4. Whether the peer's control stream begins with the
 * control stream type 0x00 and a SETTINGS frame as its first frame. Returns 1
 * if so, 0 otherwise (wrong type, a non-SETTINGS first frame, or truncation).
 */
int quic_h3conn_peer_settings_ok(const u8 *control_stream, usz len);

#endif
