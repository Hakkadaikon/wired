#ifndef QUIC_TLS_TPEXT_H
#define QUIC_TLS_TPEXT_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 8.2: QUIC carries transport parameters in a TLS extension
 * (quic_transport_parameters, extension_type 0x39). The wire form is the
 * TLS Extension: 2-byte extension_type, 2-byte extension_data length, data. */

#define QUIC_TPEXT_TYPE 0x39

/* Wrap tp_data (tp_len bytes) in the extension. Returns bytes written into
 * buf (cap total), or 0 if it does not fit or tp_len exceeds 0xFFFF. */
usz quic_tpext_encode(u8 *buf, usz cap, const u8 *tp_data, usz tp_len);

/* Parse one extension at buf (n readable). On success sets *tp_data (into
 * buf) and *tp_len, and returns total bytes consumed; 0 if truncated, the
 * extension_type is not 0x39, or the length field overruns n. */
usz quic_tpext_decode(const u8 *buf, usz n, const u8 **tp_data, usz *tp_len);

#endif
