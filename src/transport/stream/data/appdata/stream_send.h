#ifndef QUIC_APPDATA_STREAM_SEND_H
#define QUIC_APPDATA_STREAM_SEND_H

#include "common/bytes/span/span.h"
#include "transport/packet/frame/frame/frame.h"

/* RFC 9000 19.8: encode application data as a STREAM frame (type 0x08 base,
 * OFF/LEN/FIN bits set as needed) into out; length to out->len.
 * Returns 1 on success, 0 on overflow. */
int quic_appdata_stream_frame(const quic_stream_frame* f, quic_obuf* out);

#endif
