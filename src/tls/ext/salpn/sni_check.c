#include "tls/ext/salpn/sni_check.h"

#include "crypto/pki/encoding/x509/san.h"
#include "tls/ext/salpn/ch_ext.h"
#include "tls/ext/salpn/sni_extract.h"
#include "tls/handshake/core/tls/sni.h"

/* RFC 6066 3: the extracted host_name against tbs, or MALFORMED when the
 * present extension does not parse. */
static salpn_sni_outcome sni_match(wired_span ext, wired_span tbs) {
  wired_span host;
  if (!salpn_extract_sni(ext, &host)) {
    return SALPN_SNI_MALFORMED;
  }
  return x509_san_matches(tbs, host) ? SALPN_SNI_MATCH : SALPN_SNI_MISMATCH;
}

salpn_sni_outcome salpn_sni_check(
    const u8* ch_msg, usz ch_len, wired_span tbs) {
  wired_span ext;
  if (!salpn_find_extension(wired_span_of(ch_msg, ch_len), SNI_TYPE, &ext)) {
    return SALPN_SNI_ABSENT;
  }
  return sni_match(ext, tbs);
}
