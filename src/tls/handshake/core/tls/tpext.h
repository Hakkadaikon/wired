#ifndef QUIC_TLS_TPEXT_H
#define QUIC_TLS_TPEXT_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9001 8.2: QUIC carries transport parameters in a TLS extension
 * (quic_transport_parameters, extension_type 0x39). The wire form is the
 * TLS Extension: 2-byte extension_type, 2-byte extension_data length, data. */

#define QUIC_TPEXT_TYPE 0x39

/* Wrap tp in the extension. Returns bytes written into out, or 0 if it does
 * not fit or tp.n exceeds 0xFFFF. */
usz quic_tpext_encode(quic_obuf* out, quic_span tp);

/* Parse one extension at buf. On success sets *tp (a view into buf) and
 * returns total bytes consumed; 0 if truncated, the extension_type is not
 * 0x39, or the length field overruns buf. */
usz quic_tpext_decode(quic_span buf, quic_span* tp);

#endif
