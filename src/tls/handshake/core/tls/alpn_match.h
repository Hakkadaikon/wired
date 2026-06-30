#ifndef QUIC_TLS_ALPN_MATCH_H
#define QUIC_TLS_ALPN_MATCH_H

#include "common/platform/sys/syscall.h"

/* RFC 7301 3.2: the selected protocol must match one the client offered. */

/* Returns 1 if proto is exactly "h3" (0x68 0x33), else 0. */
int quic_tls_alpn_is_h3(const u8 *proto, usz len);

/* Returns 1 if the two protocol names are byte-for-byte equal, else 0. */
int quic_tls_alpn_equal(const u8 *a, usz alen, const u8 *b, usz blen);

#endif
