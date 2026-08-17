#include "app/datagram/dgdeliver/dg_loss.h"

int dgdeliver_on_loss(int is_datagram_frame) {
  return is_datagram_frame ? 1 : 0; /* RFC 9221 5.2: notify, never resend */
}

int dgdeliver_retransmit_never(void) { return 0; /* RFC 9221 5.2 */ }
