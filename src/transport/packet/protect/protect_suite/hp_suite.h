#ifndef QUIC_PROTECT_SUITE_HP_SUITE_H
#define QUIC_PROTECT_SUITE_HP_SUITE_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 5.4: derive the 5-byte header-protection mask for the given
 * cipher suite. AES suites (0x1301) use AES-ECB over the sample; ChaCha
 * suites (0x1303) use a ChaCha20 keystream block. hp_key is 16 bytes for
 * AES, 32 for ChaCha. Returns 1 on a known suite, 0 otherwise (mask
 * untouched). */
int quic_hp_suite_mask(u16 suite, const u8 *hp_key, const u8 sample[16],
                       u8 mask[5]);

#endif
