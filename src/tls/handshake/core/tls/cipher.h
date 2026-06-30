#ifndef QUIC_TLS_CIPHER_H
#define QUIC_TLS_CIPHER_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 B.4 cipher suite code points. */
#define QUIC_TLS_AES_128_GCM_SHA256       0x1301
#define QUIC_TLS_AES_256_GCM_SHA384       0x1302
#define QUIC_TLS_CHACHA20_POLY1305_SHA256 0x1303

/* Returns 1 if the suite has an implemented AEAD (0x1301/0x1303), else 0. */
int quic_cipher_supported(u16 suite);

/* RFC 8446 B.4: pick the highest-priority supported suite from the client's
 * offered list (n_pairs big-endian u16 code points). Writes it to *chosen and
 * returns 1; returns 0 if none is supported. */
int quic_cipher_select(const u8 *offered, usz n_pairs, u16 *chosen);

#endif
