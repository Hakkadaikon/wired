#ifndef SALPN_IDNA_IMPL_H
#define SALPN_IDNA_IMPL_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 3629 3: label l's code points into cps (room for l.n entries).
 * Returns the count, or 0 on malformed UTF-8 (a bad lead or continuation
 * byte, a truncated sequence, an overlong form, a surrogate, past
 * 0x10FFFF) or an empty label. */
usz salpn_idna_decode_label(wired_span l, u32* cps);

#endif
