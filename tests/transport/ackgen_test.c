#include "test.h"
#include "transport/packet/frame/frame/dispatch.h"

/* RFC 9000 13.2.1 / 13.2.2: ack a received ack-eliciting packet within
 * max_ack_delay; a second unacked one forces an immediate ack. */
static void test_ackgen_generic(void) {
  /* non-eliciting packet, nothing pending: no ack */
  CHECK(ackgen_should_ack(&(ackgen_state){0, 0, 100}, 25) == 0);

  /* first ack-eliciting packet: not due until max_ack_delay elapses */
  CHECK(ackgen_should_ack(&(ackgen_state){1, 0, 24}, 25) == 0); /* 24 < 25 */
  CHECK(ackgen_should_ack(&(ackgen_state){1, 0, 25}, 25) == 1); /* 25 >= 25 */

  /* second ack-eliciting packet while one is pending: immediate ack */
  CHECK(ackgen_should_ack(&(ackgen_state){1, 1, 0}, 25) == 1);

  /* a pending ack-eliciting packet, no new packet: delay still governs */
  CHECK(ackgen_should_ack(&(ackgen_state){0, 1, 24}, 25) == 0);
  CHECK(ackgen_should_ack(&(ackgen_state){0, 1, 25}, 25) == 1);
}

/* RFC 9221 5.2: "Receivers SHOULD support delaying ACK frames (within the
 * limits specified by max_ack_delay) in response to receiving packets that
 * only contain DATAGRAM frames" -- fed through the real frame classifier
 * (frame_ack_eliciting(FK_DATAGRAM), the same predicate
 * framedispatch_handle sets st->ack_eliciting from) rather than a
 * hand-picked 1/0, so this proves the actual DATAGRAM-only-packet path, not
 * just the generic ack_eliciting_received=1 case: a DATAGRAM-only receive
 * follows the max_ack_delay schedule exactly like any other single
 * ack-eliciting packet -- not acked immediately, but ack-due once the delay
 * elapses. */
static void test_ackgen_datagram_only_packet_delayed(void) {
  int dgram_eliciting = frame_ack_eliciting(FK_DATAGRAM);
  CHECK(dgram_eliciting == 1);

  /* within max_ack_delay: not yet due */
  CHECK(ackgen_should_ack(&(ackgen_state){dgram_eliciting, 0, 24}, 25) == 0);
  /* max_ack_delay elapsed: due */
  CHECK(ackgen_should_ack(&(ackgen_state){dgram_eliciting, 0, 25}, 25) == 1);
}

void test_ackgen(void) {
  test_ackgen_generic();
  test_ackgen_datagram_only_packet_delayed();
}
