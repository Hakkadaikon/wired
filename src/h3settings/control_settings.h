#ifndef QUIC_H3SETTINGS_CONTROL_SETTINGS_H
#define QUIC_H3SETTINGS_CONTROL_SETTINGS_H

#include "sys/syscall.h"

/* RFC 9114 6.2.1 / 7.2.4: the opening bytes of an HTTP/3 control stream:
 * stream type 0x00 followed by a SETTINGS frame with default values.
 * Returns 1 ok with *out_len set, 0 if no room. */
int quic_h3settings_control_stream(u8 *out, usz cap, usz *out_len);

#endif
