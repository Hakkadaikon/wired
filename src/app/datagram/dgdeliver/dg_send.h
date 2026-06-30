#ifndef QUIC_DGDELIVER_DG_SEND_H
#define QUIC_DGDELIVER_DG_SEND_H

#include "common/platform/sys/syscall.h"

/* RFC 9221 5: build a DATAGRAM frame for immediate delivery (no queueing, no
 * retransmit tracking by the caller). with_length picks type 0x31 (explicit
 * length) over 0x30 (data to packet end). The whole frame must fit the peer's
 * max_datagram_frame_size; otherwise 0. On success writes the frame into out
 * and stores its length in *out_len, returning 1. */
int quic_dgdeliver_frame(
    const u8 *data,
    usz       len,
    int       with_length,
    u64       max_frame_size,
    u8       *out,
    usz       cap,
    usz      *out_len);

#endif
