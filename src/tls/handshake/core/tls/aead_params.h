#ifndef QUIC_TLS_AEAD_PARAMS_H
#define QUIC_TLS_AEAD_PARAMS_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 5.3: AEAD parameters per TLS 1.3 cipher suite. */

/* Key length in bytes: AES_128_GCM 16, CHACHA20_POLY1305 32. 0 if unsupported. */
usz quic_aead_key_len(u16 suite);

/* Authentication tag length in bytes (16 for both AEADs). 0 if unsupported. */
usz quic_aead_tag_len(u16 suite);

/* Returns 1 if the suite uses ChaCha20-Poly1305 (0x1303), else 0. */
int quic_aead_is_chacha(u16 suite);

#endif
