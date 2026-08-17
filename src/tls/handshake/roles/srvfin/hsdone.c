#include "tls/handshake/roles/srvfin/hsdone.h"

/* RFC 9001 4.1.2 */
int srvfin_should_send_handshake_done(
    int handshake_complete, int already_sent) {
  return handshake_complete && !already_sent;
}

/* RFC 9000 19.20 */
int srvfin_handshake_done_frame(u8* out, usz cap, usz* out_len) {
  if (cap == 0) return 0;
  out[0]   = SRVFIN_HANDSHAKE_DONE;
  *out_len = 1;
  return 1;
}
