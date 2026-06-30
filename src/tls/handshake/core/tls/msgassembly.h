#ifndef QUIC_TLS_MSGASSEMBLY_H
#define QUIC_TLS_MSGASSEMBLY_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 4.1.3: a TLS handshake message may span several CRYPTO frames, and
 * a single frame may carry several messages. A message is complete once the
 * buffered bytes cover its 4-byte handshake header plus the declared length
 * taken from the header's 3-byte big-endian length field. */

int quic_tls_message_complete(u64 buffered, u32 declared_len);

u32 quic_tls_message_len(const u8 *hs_header);

#endif
