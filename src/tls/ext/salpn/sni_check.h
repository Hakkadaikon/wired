#ifndef QUIC_SALPN_SNI_CHECK_H
#define QUIC_SALPN_SNI_CHECK_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 6066 3: server-side check of the ClientHello's server_name extension
 * against this server's own certificate identity. */

/** Classification of a ClientHello's server_name against this server's
 * certificate identity. */
typedef enum {
  QUIC_SALPN_SNI_ABSENT = 0, /**< no server_name extension offered, or it was
                              * present but malformed (RFC 6066 3: a server
                              * MAY ignore a malformed extension) */
  QUIC_SALPN_SNI_MATCH,      /**< offered name matches tbs's SAN/CN-ID */
  QUIC_SALPN_SNI_MISMATCH    /**< offered name matches neither */
} salpn_sni_outcome;

/* Extract the server_name (RFC 6066 3) from ch_msg, if any, and check it
 * against tbs (the server's own certificate tbsCertificate, RFC 6125 6) via
 * x509_san_matches. RFC 6066 3 leaves the ABSENT and MISMATCH outcomes
 * to server policy (SHOULD NOT establish / MAY ignore): this function only
 * classifies, callers such as sdrv_recv_client_hello decide whether a
 * MISMATCH degrades to unrecognized_name (QUIC_TLS_ALERT_UNRECOGNIZED_NAME)
 * or is ignored. */
salpn_sni_outcome salpn_sni_check(const u8* ch_msg, usz ch_len, wired_span tbs);

#endif
