#include "test.h"

/* RFC 9000 13.2.1: PADDING/ACK only is non-eliciting; PING makes it eliciting.
 */
void test_eliciting(void) {
  u8 pad_only[] = {0x00, 0x00};
  CHECK(quic_pktbuild_is_eliciting(pad_only, 2) == 0);

  u8 ack_pad[] = {0x02, 0x00};
  CHECK(quic_pktbuild_is_eliciting(ack_pad, 2) == 0);

  u8 with_ping[] = {0x00, 0x01};
  CHECK(quic_pktbuild_is_eliciting(with_ping, 2) == 1);

  u8 conn_close[] = {0x1c};
  CHECK(quic_pktbuild_is_eliciting(conn_close, 1) == 0);

  /* empty packet is not ack-eliciting */
  CHECK(quic_pktbuild_is_eliciting(pad_only, 0) == 0);
}
