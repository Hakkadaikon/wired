#ifndef QUIC_APPDATA_STREAM_SEND_H
#define QUIC_APPDATA_STREAM_SEND_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 19.8: encode application data as a STREAM frame (type 0x08 base,
 * OFF/LEN/FIN bits set as needed) into out (cap bytes); length to *out_len.
 * Returns 1 on success, 0 on overflow. */
int quic_appdata_stream_frame(u64 stream_id, u64 offset,
                              const u8 *data, usz len, int fin,
                              u8 *out, usz cap, usz *out_len);

#endif
