#ifndef QUIC_FLOWVIOL_CLOSEFRAME_H
#define QUIC_FLOWVIOL_CLOSEFRAME_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 19.19: build a transport CONNECTION_CLOSE (type 0x1c) carrying the
 * error code, the type of the frame that triggered the violation, and a reason
 * phrase. A thin wrapper over quic_frame_put_conn_close fixing the transport
 * variant. */

/* Writes the frame to out (cap bytes) and the length to *out_len. Returns 1 on
 * success, 0 on overflow. reason may be 0 when reason_len is 0. */
int quic_flowviol_close_frame(u64 error_code, u64 frame_type,
                              const u8 *reason, usz reason_len,
                              u8 *out, usz cap, usz *out_len);

#endif
