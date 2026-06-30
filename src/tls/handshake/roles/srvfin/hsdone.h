#ifndef QUIC_SRVFIN_HSDONE_H
#define QUIC_SRVFIN_HSDONE_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 4.1.2 / RFC 9000 19.20: the server sends a HANDSHAKE_DONE frame
 * (type 0x1e) once the handshake is complete, to signal confirmation to the
 * client. It is sent exactly once. */

#define QUIC_SRVFIN_HANDSHAKE_DONE 0x1e

/* 1 if the server should send HANDSHAKE_DONE now: complete and not yet sent. */
int quic_srvfin_should_send_handshake_done(int handshake_complete,
                                           int already_sent);

/* Write the single-byte HANDSHAKE_DONE frame. Returns 1 and sets *out_len=1,
 * or 0 if cap is 0. */
int quic_srvfin_handshake_done_frame(u8 *out, usz cap, usz *out_len);

#endif
