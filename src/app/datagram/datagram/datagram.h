#ifndef DATAGRAM_DATAGRAM_H
#define DATAGRAM_DATAGRAM_H

#include "common/bytes/span/span.h"

/* RFC 9221 unreliable datagram extension. The DATAGRAM frame type 0x30 has
 * no length (data runs to the packet end); 0x31 carries an explicit length.
 * Datagrams are ack-eliciting but never retransmitted. */

#define FRAME_DATAGRAM 0x30     /* no LEN */
#define FRAME_DATAGRAM_LEN 0x31 /* LEN bit set */
#define DATAGRAM_LEN_BIT 0x01

/* max_datagram_frame_size transport parameter (RFC 9221 3). */
#define TP_MAX_DATAGRAM_FRAME_SIZE 0x20

/** RFC 9221: a decoded DATAGRAM frame view (data borrowed in place). */
typedef struct {
  u64       length; /* data length */
  const u8* data;   /* view into the packet buffer */
} datagram_frame;

/* Encode a DATAGRAM frame into buf. When with_len is set the frame is type
 * 0x31 (explicit length); otherwise 0x30 and the data must be the last frame
 * in the packet. Returns bytes written, or 0. */
usz datagram_encode(wired_mspan buf, const datagram_frame* f, int with_len);

/* Decode a DATAGRAM frame at buf (n readable, type byte at buf[0]). For 0x30
 * the data is the rest of the buffer; for 0x31 the length is explicit.
 * Fills *f (data points into buf) and returns bytes consumed, or 0. */
usz datagram_decode(const u8* buf, usz n, datagram_frame* f);

/* Whether a datagram of size frame_len may be sent given the peer's
 * advertised max_datagram_frame_size (0 means datagrams are not supported). */
int datagram_allowed(u64 max_datagram_frame_size, u64 frame_len);

#endif
