#ifndef QUIC_TLS_ALPN_H
#define QUIC_TLS_ALPN_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 7301 3.1: ALPN extension, extension_type 0x0010. ProtocolNameList =
 * list length(2) + (name length(1) + name)*. */

#define QUIC_ALPN_TYPE 0x0010

/* Encode a ProtocolNameList holding one protocol: list length(2) +
 * name length(1) + proto. Returns bytes written into out, or 0 if it does not
 * fit or proto.n is 0 or exceeds 0xFF. */
usz quic_tls_alpn_encode(quic_obuf* out, quic_span proto);

/* Read the first protocol of the ProtocolNameList at buf. On success sets
 * *proto (a view into buf) and returns total bytes consumed by the whole
 * list; 0 if truncated or a length field overruns. */
usz quic_tls_alpn_decode_first(quic_span buf, quic_span* proto);

#endif
