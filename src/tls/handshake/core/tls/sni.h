#ifndef TLS_SNI_H
#define TLS_SNI_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 6066 3: server_name extension, extension_type 0x0000. host_name only. */

#define SNI_TYPE 0x0000
#define SNI_HOST_NAME 0x00

/* Encode a ServerNameList holding one host_name entry: name_type(1)=0 +
 * name length(2) + host. Returns bytes written into out, or 0 if it does not
 * fit or host.n exceeds 0xFFFF. */
usz tls_sni_encode(wired_obuf* out, wired_span host);

/* Parse the host_name entry at buf. On success sets *host (a view into buf)
 * and returns total bytes consumed; 0 if truncated, the name_type is not
 * host_name, or the length field overruns buf. */
usz tls_sni_decode(wired_span buf, wired_span* host);

#endif
