#ifndef QUIC_TLS_RETRY_TAG_V2_H
#define QUIC_TLS_RETRY_TAG_V2_H

#include "common/platform/sys/syscall.h"

/* RFC 9369 3.3.3 fixed key and nonce for the QUIC v2 Retry Integrity Tag. */

void quic_retry_tag_v2_key(const u8 **key, usz *len);
void quic_retry_tag_v2_nonce(const u8 **nonce, usz *len);

#endif
