#include "tls/ext/salpn/sni_extract.h"

#include "tls/handshake/core/tls/sni.h"

/* RFC 6066 3. */

/* The 2-byte server_name_list length is the whole rest of sni_ext. */
static int sni_list_exact(wired_span sni_ext, usz* list_len) {
  if (sni_ext.n < 2) {
    return 0;
  }
  *list_len = (usz)sni_ext.p[0] << 8 | sni_ext.p[1];
  return 2 + *list_len == sni_ext.n;
}

/* The one host_name entry decoded (used != 0), filled the list exactly, and
 * is non-empty (HostName<1..2^16-1>). */
static int sni_entry_exact(usz used, usz list_len, const wired_span* host) {
  return used != 0 && used == list_len && host->n != 0;
}

int salpn_extract_sni(wired_span sni_ext, wired_span* host) {
  usz list_len;
  if (!sni_list_exact(sni_ext, &list_len)) {
    return 0;
  }
  return sni_entry_exact(
      tls_sni_decode(wired_span_of(sni_ext.p + 2, list_len), host), list_len,
      host);
}
