#ifndef TLS_ALPN_H
#define TLS_ALPN_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 7301 3.1: ALPN extension, extension_type 0x0010. ProtocolNameList =
 * list length(2) + (name length(1) + name)*. */

#define ALPN_TYPE 0x0010

/* Encode a ProtocolNameList holding one protocol: list length(2) +
 * name length(1) + proto. Returns bytes written into out, or 0 if it does not
 * fit or proto.n is 0 or exceeds 0xFF. */
usz tls_alpn_encode(wired_obuf* out, wired_span proto);

/* Read the first protocol of the ProtocolNameList at buf. On success sets
 * *proto (a view into buf) and returns total bytes consumed by the whole
 * list; 0 if truncated or a length field overruns. */
usz tls_alpn_decode_first(wired_span buf, wired_span* proto);

#endif
