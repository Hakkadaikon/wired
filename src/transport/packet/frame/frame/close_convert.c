#include "transport/packet/frame/frame/close_convert.h"

/* RFC 9000 10.2.3 */
int close_needs_convert(int is_app_close, int in_handshake) {
  return is_app_close && in_handshake;
}

int close_converted_type(void) { return CLOSE_TRANSPORT; }
