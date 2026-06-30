#ifndef QUIC_TLSEXT_PSKMODES_H
#define QUIC_TLSEXT_PSKMODES_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.2.9: psk_key_exchange_modes, extension_type 0x002d. Body is a
 * 1-byte ke_modes list length followed by that many 1-byte modes. This codec
 * offers psk_dhe_ke(1) only, the mode QUIC requires. */

#define QUIC_TLSEXT_PSK_DHE_KE 0x01

/* Encode psk_key_exchange_modes offering psk_dhe_ke only into out (cap total).
 * Writes the byte count to *out_len. Returns 1, or 0 if it does not fit. */
int quic_tlsext_psk_modes(u8 *out, usz cap, usz *out_len);

/* Parse the extension at out (n readable) and report whether psk_dhe_ke is in
 * the ke_modes list. Returns 1 if present, 0 if absent or malformed. */
int quic_tlsext_psk_modes_parse(const u8 *out, usz n);

#endif
