#ifndef QUIC_SELFCERT_SELFCERT_H
#define QUIC_SELFCERT_SELFCERT_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1 / RFC 8410. Build a self-signed Ed25519 X.509 certificate from
 * a 32-byte seed into cert_out, setting cert_out->len. Returns 1 ok, 0 on
 * failure (no room, or key/sign error). */
int quic_selfcert_build(const u8 seed[32], quic_obuf* cert_out);

#endif
