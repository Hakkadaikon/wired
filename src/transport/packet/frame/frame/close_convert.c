#include "transport/packet/frame/frame/close_convert.h"

/* RFC 9000 10.2.3 */
int quic_close_needs_convert(int is_app_close, int in_handshake) {
  return is_app_close && in_handshake;
}

int quic_close_converted_type(void) { return QUIC_CLOSE_TRANSPORT; }
