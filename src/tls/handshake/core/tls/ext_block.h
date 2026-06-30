#ifndef QUIC_TLS_EXT_BLOCK_H
#define QUIC_TLS_EXT_BLOCK_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.1.2: the ClientHello extensions field is a 2-byte total length
 * followed by the concatenated extensions. Build it by reserving the length,
 * appending extensions, then back-filling the length. */

/* Reserve the 2-byte length at buf and set *off to just past it. Returns 1,
 * or 0 if cap is below 2. */
int quic_tls_ext_block_begin(const u8 *buf, usz cap, usz *off);

/* Append ext_len bytes of ext at *off (cap total). Returns 1, 0 if no room. */
int quic_tls_ext_append(u8 *buf, usz cap, usz *off, const u8 *ext, usz ext_len);

/* Back-fill the 2-byte length at block_start to cover everything appended
 * since begin. Returns the final block length written (off), or 0 if the body
 * exceeds 0xFFFF. */
usz quic_tls_ext_block_finish(u8 *buf, usz off, usz block_start);

#endif
