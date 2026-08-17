#ifndef TBSCERT_VERSION_SERIAL_H
#define TBSCERT_VERSION_SERIAL_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "crypto/pki/cert/tbscert/fields.h"

/* RFC 5280 4.1.2.1. version: v1=0, v2=1, v3=2. Absent [0] defaults to v1 (0).
 */
int tbscert_version(const tbscert* t, u64* out);

/* RFC 5280 4.1.2.2. serialNumber INTEGER value (<= 20 octets). Views into the
 * tbs buffer. Returns 1 ok, 0 if absent or longer than 20 octets. */
int tbscert_serial(const tbscert* t, wired_span* serial);

#endif
