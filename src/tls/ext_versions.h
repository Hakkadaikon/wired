#ifndef QUIC_TLS_EXT_VERSIONS_H
#define QUIC_TLS_EXT_VERSIONS_H

#include "sys/syscall.h"
#include "tls/handshake.h"

/* RFC 8446 4.2.1: supported_versions, extension_type 0x002b. In ClientHello
 * the body is a 1-byte list length followed by 2-byte versions. */

#define QUIC_TLS13_VERSION 0x0304

/* Encode the supported_versions extension offering TLS 1.3 only. Returns
 * bytes written into buf (cap total), or 0 if it does not fit. */
usz quic_tls_ext_supported_versions(u8 *buf, usz cap);

/* Parse the extension at buf (n readable) and report whether TLS 1.3 is in
 * the version list. Returns 1 if present, 0 if absent or malformed. */
int quic_tls_ext_versions_has_tls13(const u8 *buf, usz n);

#endif
