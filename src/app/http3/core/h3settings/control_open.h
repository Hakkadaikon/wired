#ifndef QUIC_H3SETTINGS_CONTROL_OPEN_H
#define QUIC_H3SETTINGS_CONTROL_OPEN_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 6.2.1: a control stream begins with stream type 0x00 (varint).
 * Writes that leading byte. Returns 1 ok with *out_len set, 0 if no room. */
int quic_h3settings_control_prefix(u8* out, usz cap, usz* out_len);

#endif
