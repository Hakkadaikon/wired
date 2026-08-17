#include "tls/handshake/core/tls/keyupdate_reject.h"

#include "common/diag/error/error.h"

/* RFC 9001 6 */
int tls_keyupdate_is_forbidden(u8 msg_type) {
  return msg_type == HS_KEY_UPDATE;
}

/* RFC 9001 6 / RFC 8446 B.2: unexpected_message = alert 10. */
u64 tls_keyupdate_reject_code(void) { return err_crypto(10); }
