#include "tls/ext/salpn/sni_extract.h"

#include "tls/handshake/core/tls/sni.h"

/* RFC 6066 3. */

int quic_salpn_extract_sni(quic_span sni_ext, quic_span *host) {
  usz       list_len;
  const u8 *hostname;
  usz       host_len;
  int       ok;
  if (sni_ext.n < 2) return 0;
  list_len = (usz)sni_ext.p[0] << 8 | sni_ext.p[1];
  if (2 + list_len > sni_ext.n) return 0;
  ok = quic_tls_sni_decode(sni_ext.p + 2, list_len, &hostname, &host_len) != 0;
  *host = quic_span_of(hostname, host_len);
  return ok;
}
