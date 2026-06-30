#ifndef QUIC_FRAME_NCID_H
#define QUIC_FRAME_NCID_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 19.15 NEW_CONNECTION_ID: issues a new connection ID with a
 * stateless reset token. */

#define QUIC_FRAME_NEW_CID 0x18
#define QUIC_NCID_TOKEN    16
#define QUIC_NCID_MAX_LEN  20

typedef struct {
    u64 seq;            /* sequence number */
    u64 retire_prior_to;
    u8  cid_len;
    u8  cid[QUIC_NCID_MAX_LEN];
    u8  token[QUIC_NCID_TOKEN]; /* stateless reset token */
} quic_ncid_frame;

/* Encode into buf of cap bytes. Returns bytes written, or 0 on overflow /
 * invalid (cid_len out of range, or retire_prior_to > seq). */
usz quic_ncid_encode(u8 *buf, usz cap, const quic_ncid_frame *f);

/* Decode at buf (n readable, type byte 0x18 at buf[0]). Returns bytes
 * consumed, or 0 on malformed / truncated input. */
usz quic_ncid_decode(const u8 *buf, usz n, quic_ncid_frame *f);

#endif
