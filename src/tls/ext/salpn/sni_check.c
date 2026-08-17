#include "tls/ext/salpn/sni_check.h"

#include "crypto/pki/encoding/x509/san.h"
#include "tls/ext/salpn/ch_ext.h"
#include "tls/ext/salpn/sni_extract.h"
#include "tls/handshake/core/tls/sni.h"

/* RFC 6066 3: locate the server_name extension and extract its host_name, if
 * any is present and well-formed. */
static int sni_take_host(const u8* ch_msg, usz ch_len, wired_span* host) {
  wired_span ext;
  if (!quic_salpn_find_extension(
          wired_span_of(ch_msg, ch_len), QUIC_SNI_TYPE, &ext))
    return 0;
  return quic_salpn_extract_sni(ext, host);
}

quic_salpn_sni_outcome quic_salpn_sni_check(
    const u8* ch_msg, usz ch_len, wired_span tbs) {
  wired_span host;
  if (!sni_take_host(ch_msg, ch_len, &host)) return QUIC_SALPN_SNI_ABSENT;
  return x509_san_matches(tbs, host) ? QUIC_SALPN_SNI_MATCH
                                     : QUIC_SALPN_SNI_MISMATCH;
}
