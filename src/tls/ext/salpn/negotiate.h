#ifndef QUIC_SALPN_NEGOTIATE_H
#define QUIC_SALPN_NEGOTIATE_H

#include "common/platform/sys/syscall.h"

/* RFC 7301: server-side ALPN. The client offers a ProtocolNameList in its
 * ALPN extension (extension_type 0x0010); the server picks one and echoes it
 * in EncryptedExtensions. QUIC (RFC 9114) selects "h3". */

#define QUIC_SALPN_EXT_TYPE 0x0010

/* Return 1 if the ProtocolNameList in alpn_ext_data (len bytes) offers "h3"
 * (0x68 0x33), else 0 (absent, truncated, or a length field overruns). */
int quic_salpn_select_h3(const u8 *alpn_ext_data, usz len);

/* Build the EncryptedExtensions ALPN extension selecting "h3":
 * ext_type(2)=0x0010 ext_data_len(2) list_len(2) name_len(1) "h3".
 * Writes into out (cap total), sets *out_len, returns 1; 0 if cap < 9. */
int quic_salpn_build_response(u8 *out, usz cap, usz *out_len);

#endif
