#ifndef QUIC_TLS_HP_SELECT_H
#define QUIC_TLS_HP_SELECT_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 5.4.3: header protection algorithm per cipher suite. */

/* Returns 1 if header protection uses ChaCha20 (0x1303), else AES (0). */
int quic_hp_is_chacha(u16 suite);

/* HP key length in bytes: AES 16, ChaCha20 32. 0 if unsupported. */
usz quic_hp_key_len(u16 suite);

#endif
