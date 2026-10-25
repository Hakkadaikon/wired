#ifndef SALPN_PUNYCODE_H
#define SALPN_PUNYCODE_H

#include "common/platform/sys/syscall.h"

/* RFC 3492 6.3: Punycode-encode the n code points at cp (each at most
 * 0x10FFFF, n at most 255 so delta cannot overflow 32 bits) into out:
 * the basic (ASCII) code points in order, a '-' when there were any, then
 * the encoded deltas of the rest. Returns the bytes written, or 0 if they
 * do not fit cap. Case is kept as given (no mixed-case annotation). */
usz salpn_punycode_encode(const u32* cp, usz n, u8* out, usz cap);

#endif
