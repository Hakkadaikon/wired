#ifndef QUIC_DATAGRAM_DATAGRAM_H
#define QUIC_DATAGRAM_DATAGRAM_H

#include "common/platform/sys/syscall.h"

/* RFC 9221 unreliable datagram extension. The DATAGRAM frame type 0x30 has
 * no length (data runs to the packet end); 0x31 carries an explicit length.
 * Datagrams are ack-eliciting but never retransmitted. */

#define QUIC_FRAME_DATAGRAM 0x30     /* no LEN */
#define QUIC_FRAME_DATAGRAM_LEN 0x31 /* LEN bit set */
#define QUIC_DATAGRAM_LEN_BIT 0x01

/* max_datagram_frame_size transport parameter (RFC 9221 3). */
#define QUIC_TP_MAX_DATAGRAM_FRAME_SIZE 0x20

typedef struct {
  u64       length; /* data length */
  const u8 *data;   /* view into the packet buffer */
} quic_datagram_frame;

/* Encode a DATAGRAM frame into buf of cap bytes. When with_len is set the
 * frame is type 0x31 (explicit length); otherwise 0x30 and the data must be
 * the last frame in the packet. Returns bytes written, or 0. */
usz quic_datagram_encode(
    u8 *buf, usz cap, const quic_datagram_frame *f, int with_len);

/* Decode a DATAGRAM frame at buf (n readable, type byte at buf[0]). For 0x30
 * the data is the rest of the buffer; for 0x31 the length is explicit.
 * Fills *f (data points into buf) and returns bytes consumed, or 0. */
usz quic_datagram_decode(const u8 *buf, usz n, quic_datagram_frame *f);

/* Whether a datagram of size frame_len may be sent given the peer's
 * advertised max_datagram_frame_size (0 means datagrams are not supported). */
int quic_datagram_allowed(u64 max_datagram_frame_size, u64 frame_len);

#endif
