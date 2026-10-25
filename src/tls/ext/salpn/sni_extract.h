#ifndef SALPN_SNI_EXTRACT_H
#define SALPN_SNI_EXTRACT_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 6066 3: extract the host_name from a server_name extension's data
 * (extension_type 0x0000). sni_ext is the ServerNameList:
 * list_len(2) name_type(1)=0 name_len(2) host. */

/* On success sets *host (a view into sni_ext.p) and returns 1; 0 if the
 * extension is malformed: truncated, a length field overruns or falls short
 * of sni_ext.n, the list or the HostName is empty (server_name_list<1..>,
 * HostName<1..>), the name_type is not host_name, or bytes follow the one
 * entry (one name per name_type; host_name is the only type). */
int salpn_extract_sni(wired_span sni_ext, wired_span* host);

#endif
