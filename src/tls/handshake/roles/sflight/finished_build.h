#ifndef QUIC_SFLIGHT_FINISHED_BUILD_H
#define QUIC_SFLIGHT_FINISHED_BUILD_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.4.4: build the server Finished message (type 0x14). Computes
 * verify_data = HMAC(HKDF-Expand-Label(finished_key, "finished"),
 * transcript_hash) and writes the 32-byte verify_data into the handshake
 * message at out (cap total), setting *out_len. Returns 1, or 0 if it does
 * not fit. finished_key is the server handshake traffic secret. */
int quic_sflight_finished(const u8 *finished_key, const u8 *transcript_hash,
                          u8 *out, usz cap, usz *out_len);

#endif
