#include "tls/handshake/core/tls/hs_message.h"

/* RFC 8446 4 */

int quic_hs_message_ready(const u8 *buf, usz buffered, usz *msg_len) {
  if (buffered < QUIC_HS_HEADER) return 0;
  usz body  = ((usz)buf[1] << 16) | ((usz)buf[2] << 8) | buf[3];
  usz total = QUIC_HS_HEADER + body;
  if (buffered < total) return 0;
  *msg_len = total;
  return 1;
}

u8 quic_hs_message_type(const u8 *buf) { return buf[0]; }
