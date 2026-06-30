#ifndef QUIC_TLSEXT_EARLYDATA_H
#define QUIC_TLSEXT_EARLYDATA_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.2.10: early_data, extension_type 0x002a. The body is empty in
 * ClientHello and EncryptedExtensions, and a 4-byte max_early_data_size in
 * NewSessionTicket. */

/* Encode the empty ClientHello early_data extension into out (cap total).
 * Writes the byte count to *out_len. Returns 1, or 0 if it does not fit. */
int quic_tlsext_early_data_ch(u8 *out, usz cap, usz *out_len);

/* Encode the NewSessionTicket early_data extension carrying max_size into out
 * (cap total). Writes the byte count to *out_len. Returns 1, or 0 if it does
 * not fit. */
int quic_tlsext_early_data_nst(u32 max_size, u8 *out, usz cap, usz *out_len);

/* Parse the NewSessionTicket form at out (n readable), reporting max_size via
 * *max_size. Returns 1 on success, 0 if absent or malformed. */
int quic_tlsext_early_data_nst_parse(const u8 *out, usz n, u32 *max_size);

#endif
