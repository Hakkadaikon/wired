#ifndef QUIC_SALPN_SNI_EXTRACT_H
#define QUIC_SALPN_SNI_EXTRACT_H

#include "common/platform/sys/syscall.h"

/* RFC 6066 3: extract the host_name from a server_name extension's data
 * (extension_type 0x0000). sni_ext_data is the ServerNameList:
 * list_len(2) name_type(1)=0 name_len(2) host. */

/* On success sets *hostname (a view into sni_ext_data) and *host_len, and
 * returns 1; 0 if truncated, the name_type is not host_name, or a length
 * field overruns len. */
int quic_salpn_extract_sni(const u8 *sni_ext_data, usz len,
                           const u8 **hostname, usz *host_len);

#endif
