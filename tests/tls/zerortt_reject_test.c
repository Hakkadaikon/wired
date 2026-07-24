#include "test.h"

/* RFC 9001 4.6.1 */
void test_zerortt_reject(void) {
  int retransmit = 0, discard = 0;
  quic_zerortt_on_reject(&retransmit, &discard);
  CHECK(retransmit == 1);
  CHECK(discard == 1);

  CHECK(quic_zerortt_accepted(1) == 1);
  CHECK(quic_zerortt_accepted(0) == 0);
  CHECK(quic_zerortt_accepted(7) == 1);

  /* RFC 9001 4.9.3: 0-RTT keys are discarded 3*PTO after the first 1-RTT
   * packet is received. */
  CHECK(!quic_zerortt_should_discard(1000, 1000, 100)); /* just received */
  CHECK(!quic_zerortt_should_discard(1000, 1299, 100)); /* short of 3*PTO */
  CHECK(quic_zerortt_should_discard(1000, 1300, 100));  /* exactly 3*PTO */
  CHECK(quic_zerortt_should_discard(1000, 5000, 100));  /* long past */
}
