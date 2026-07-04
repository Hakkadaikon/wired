#ifndef QUIC_H3_HEADERCASE_H
#define QUIC_H3_HEADERCASE_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 4.3. Field names in HTTP/3 MUST be lowercase. A field name that
 * contains an uppercase letter MUST be treated as malformed (H3_MESSAGE_ERROR).
 * Returns 1 if name (len bytes) contains no uppercase A-Z, 0 otherwise. */
int quic_h3_header_name_ok(const u8* name, usz len);

#endif
