#ifndef QUIC_HP_HP_H
#define QUIC_HP_HP_H

#include "crypto/symmetric/aead/aes/aes.h"

/* RFC 9001 5.4 header protection for AES-based suites. The mask is
 * AES-ECB(hp_key, sample); sample is 16 ciphertext bytes taken at
 * pn_offset+4. byte0's low bits and the packet number bytes are masked. */

#define QUIC_HP_SAMPLE 16
#define QUIC_HP_LONG_MASK  0x0f /* long header: mask 4 low bits of byte0 */
#define QUIC_HP_SHORT_MASK 0x1f /* short header: mask 5 low bits of byte0 */

/* Compute the 5-byte header-protection mask from a 16-byte sample. */
void quic_hp_mask(const quic_aes128 *hp, const u8 sample[QUIC_HP_SAMPLE],
                  u8 mask[5]);

/* Apply (or remove — XOR is its own inverse) header protection in place:
 * byte0's low bits (per bits_mask) and pn_len packet-number bytes at pn. */
void quic_hp_apply(const u8 mask[5], u8 *byte0, u8 *pn, usz pn_len,
                   u8 bits_mask);

#endif
