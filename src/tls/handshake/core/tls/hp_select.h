#ifndef TLS_HP_SELECT_H
#define TLS_HP_SELECT_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 5.4.3: header protection algorithm per cipher suite. */

/* HP key length in bytes: AES-128 16, AES-256 and ChaCha20 32. 0 if
 * unsupported. */
usz hp_key_len(u16 suite);

#endif
