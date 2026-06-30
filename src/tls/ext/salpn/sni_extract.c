#include "tls/ext/salpn/sni_extract.h"

#include "tls/handshake/core/tls/sni.h"

/* RFC 6066 3. */

int quic_salpn_extract_sni(
    const u8 *sni_ext_data, usz len, const u8 **hostname, usz *host_len) {
  usz list_len;
  if (len < 2) return 0;
  list_len = (usz)sni_ext_data[0] << 8 | sni_ext_data[1];
  if (2 + list_len > len) return 0;
  return quic_tls_sni_decode(sni_ext_data + 2, list_len, hostname, host_len) !=
         0;
}
