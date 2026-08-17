#include "test.h"

/* RFC 9000 13.2.7: while sending only non-ack-eliciting (e.g. PADDING-only)
 * packets, periodically bundle an ack-eliciting frame -- due once at least
 * one PTO has elapsed since the last ack-eliciting send. */
void test_paddingelicit(void) {
  /* just sent an ack-eliciting packet: not due yet */
  CHECK(pktbuild_padding_elicit_due(1000, 1000, 100) == 0);
  CHECK(pktbuild_padding_elicit_due(1000, 1000 + 99, 100) == 0);

  /* exactly one PTO elapsed: due */
  CHECK(pktbuild_padding_elicit_due(1000, 1000 + 100, 100) == 1);
  /* well past one PTO: still due */
  CHECK(pktbuild_padding_elicit_due(1000, 1000 + 1000, 100) == 1);

  /* never sent an ack-eliciting packet (last_eliciting_at == 0): due once
   * `now` alone reaches one PTO */
  CHECK(pktbuild_padding_elicit_due(0, 99, 100) == 0);
  CHECK(pktbuild_padding_elicit_due(0, 100, 100) == 1);
}
