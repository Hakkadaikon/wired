#ifndef QUIC_FRAME_CONNCTL_H
#define QUIC_FRAME_CONNCTL_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 19: connection and path management frames. */

#define QUIC_FRAME_NEW_TOKEN       0x07 /* 19.7  */
#define QUIC_FRAME_RETIRE_CID      0x19 /* 19.16 */
#define QUIC_FRAME_PATH_CHALLENGE  0x1a /* 19.17 */
#define QUIC_FRAME_PATH_RESPONSE   0x1b /* 19.18 */
#define QUIC_FRAME_HANDSHAKE_DONE  0x1e /* 19.20 */

#define QUIC_PATH_DATA 8 /* PATH_CHALLENGE/RESPONSE payload length */

/* NEW_TOKEN (19.7): a token length and a view into the token (not copied).
 * length 0 is permitted. */
typedef struct {
    u64 length;
    const u8 *token;
} quic_new_token_frame;

/* Encode/decode NEW_TOKEN. Returns bytes written/consumed, 0 on
 * overflow or malformed/truncated input. */
usz quic_new_token_encode(u8 *buf, usz cap, const quic_new_token_frame *f);
usz quic_new_token_decode(const u8 *buf, usz n, quic_new_token_frame *f);

/* RETIRE_CONNECTION_ID (19.16): a single sequence number. */
usz quic_retire_cid_encode(u8 *buf, usz cap, u64 seq);
usz quic_retire_cid_decode(const u8 *buf, usz n, u64 *seq);

/* PATH_CHALLENGE/PATH_RESPONSE (19.17/19.18): an 8-byte payload. type is
 * QUIC_FRAME_PATH_CHALLENGE or QUIC_FRAME_PATH_RESPONSE. */
usz quic_path_encode(u8 *buf, usz cap, u8 type, const u8 data[QUIC_PATH_DATA]);
usz quic_path_decode(const u8 *buf, usz n, u8 type, u8 data[QUIC_PATH_DATA]);

/* HANDSHAKE_DONE (19.20): type byte only, no body. */
usz quic_handshake_done_encode(u8 *buf, usz cap);
usz quic_handshake_done_decode(const u8 *buf, usz n);

#endif
