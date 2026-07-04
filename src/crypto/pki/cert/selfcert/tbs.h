#ifndef QUIC_SELFCERT_TBS_H
#define QUIC_SELFCERT_TBS_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1. Build a v3 TBSCertificate (self-issued CN=localhost, fixed
 * validity, Ed25519 SPKI) into out, setting out->len to the whole SEQUENCE
 * length. Returns 1 ok, 0 if it would not fit. */
int quic_selfcert_tbs(const u8 pub[32], quic_obuf* out);

#endif
