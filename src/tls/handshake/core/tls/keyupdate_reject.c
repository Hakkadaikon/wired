#include "tls/handshake/core/tls/keyupdate_reject.h"

#include "common/diag/error/error.h"

/* RFC 9001 6 */
int quic_tls_keyupdate_is_forbidden(u8 msg_type) {
  return msg_type == QUIC_HS_KEY_UPDATE;
}

/* RFC 9001 6 / RFC 8446 B.2: unexpected_message = alert 10. */
u64 quic_tls_keyupdate_reject_code(void) { return quic_err_crypto(10); }
