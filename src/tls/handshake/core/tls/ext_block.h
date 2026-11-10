#ifndef TLS_EXT_BLOCK_H
#define TLS_EXT_BLOCK_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 8446 4.1.2: the ClientHello extensions field is a 2-byte total length
 * followed by the concatenated extensions. Build it by reserving the length,
 * appending extensions, then back-filling the length. */

/* Append ext to out (advancing out->len). Returns 1, 0 if no room. */
int tls_ext_append(wired_obuf* out, wired_span ext);

/* Back-fill the 2-byte length at block_start to cover everything appended
 * after it. Returns the final block length written (off), or 0 if the body
 * exceeds 0xFFFF. */
usz tls_ext_block_finish(u8* buf, usz off, usz block_start);

#endif
