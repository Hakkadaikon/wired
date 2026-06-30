#ifndef QUIC_TLS_HS_MESSAGE_H
#define QUIC_TLS_HS_MESSAGE_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4: handshake message framing (type:1 length:3 body). */

#define QUIC_HS_HEADER 4

/* 1 if a complete message is present, writing its total size (4+body) to
 * *msg_len; 0 if more bytes are needed. */
int quic_hs_message_ready(const u8 *buf, usz buffered, usz *msg_len);

/* msg_type of the message at buf. Caller ensures buffered >= 1. */
u8 quic_hs_message_type(const u8 *buf);

#endif
