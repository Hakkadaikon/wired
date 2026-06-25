#ifndef QUIC_FRAME_FRAME_H
#define QUIC_FRAME_FRAME_H

#include "sys/syscall.h"

/* RFC 9000 19: frame types. The type itself is a varint; the common ones
 * below fit in a single byte. */

#define QUIC_FRAME_PADDING          0x00
#define QUIC_FRAME_PING             0x01
#define QUIC_FRAME_CRYPTO           0x06
#define QUIC_FRAME_STREAM_BASE      0x08 /* 0x08-0x0f, low 3 bits = OFF/LEN/FIN */
#define QUIC_FRAME_CONN_CLOSE_TPT   0x1c
#define QUIC_FRAME_CONN_CLOSE_APP   0x1d

/* STREAM type bits (RFC 9000 19.8). */
#define QUIC_STREAM_FIN  0x01
#define QUIC_STREAM_LEN  0x02
#define QUIC_STREAM_OFF  0x04

/* A CRYPTO frame: offset + a view into the data (not copied). */
typedef struct {
    u64 offset;
    u64 length;
    const u8 *data;
} quic_crypto_frame;

/* Encode a single-byte type frame (PADDING or PING) into buf of cap bytes.
 * Returns bytes written (1) or 0 if no room. */
usz quic_frame_put_simple(u8 *buf, usz cap, u8 type);

/* Encode a CRYPTO frame header + data into buf of cap bytes.
 * Returns total bytes written, or 0 if out of range / no room. */
usz quic_frame_put_crypto(u8 *buf, usz cap, const quic_crypto_frame *f);

/* Decode a CRYPTO frame at buf (n readable, type byte already at buf[0]).
 * Fills *f (data points into buf) and returns bytes consumed, or 0. */
usz quic_frame_get_crypto(const u8 *buf, usz n, quic_crypto_frame *f);

#endif
