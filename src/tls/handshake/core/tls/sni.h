#ifndef QUIC_TLS_SNI_H
#define QUIC_TLS_SNI_H

#include "common/platform/sys/syscall.h"

/* RFC 6066 3: server_name extension, extension_type 0x0000. host_name only. */

#define QUIC_SNI_TYPE 0x0000
#define QUIC_SNI_HOST_NAME 0x00

/* Encode a ServerNameList holding one host_name entry: name_type(1)=0 +
 * name length(2) + host. Returns bytes written into buf (cap total), or 0 if
 * it does not fit or host_len exceeds 0xFFFF. */
usz quic_tls_sni_encode(u8 *buf, usz cap, const u8 *host, usz host_len);

/* Parse the host_name entry at buf (n readable). On success sets *host (into
 * buf) and *host_len, and returns total bytes consumed; 0 if truncated, the
 * name_type is not host_name, or the length field overruns n. */
usz quic_tls_sni_decode(const u8 *buf, usz n, const u8 **host, usz *host_len);

#endif
