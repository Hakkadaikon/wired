#ifndef SALPN_SNI_CHECK_H
#define SALPN_SNI_CHECK_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 6066 3: server-side check of the ClientHello's server_name extension
 * against this server's own certificate identity. */

/** Classification of a ClientHello's server_name against this server's
 * certificate identity. */
typedef enum {
  SALPN_SNI_ABSENT = 0, /**< no server_name extension offered */
  SALPN_SNI_MATCH,      /**< offered name matches tbs's SAN/CN-ID */
  SALPN_SNI_MISMATCH,   /**< offered name matches neither */
  /** present but unparseable (salpn_extract_sni): RFC 6066 3's
   * <1..2^16-1> bounds, RFC 8446 6.2 decode_error */
  SALPN_SNI_MALFORMED
} salpn_sni_outcome;

/* Extract the server_name (RFC 6066 3) from ch_msg into *host (a view into
 * ch_msg, set on MATCH and MISMATCH), if any, and check it
 * against tbs (the server's own certificate tbsCertificate, RFC 6125 6) via
 * x509_san_matches. A present extension salpn_extract_sni rejects is
 * MALFORMED. RFC 6066 3 leaves the ABSENT and MISMATCH outcomes
 * to server policy (SHOULD NOT establish / MAY ignore): this function only
 * classifies, callers such as sdrv_recv_client_hello decide whether a
 * MISMATCH degrades to unrecognized_name (TLS_ALERT_UNRECOGNIZED_NAME)
 * or is ignored. */
salpn_sni_outcome salpn_sni_check(
    const u8* ch_msg, usz ch_len, wired_span tbs, wired_span* host);

/** Bytes of a salpn_sni_digest. */
#define SALPN_SNI_DIGEST 32

/* RFC 6066 3 / RFC 6125 6.4.1: SHA-256 of host ASCII-lowercased, so two
 * names that compare equal (case-insensitively) digest equal; host.n 0 (no
 * server_name) is all zero, never a real digest. What a session ticket
 * records to refuse resumption under a different server_name. */
void salpn_sni_digest(wired_span host, u8 out[SALPN_SNI_DIGEST]);

#endif
