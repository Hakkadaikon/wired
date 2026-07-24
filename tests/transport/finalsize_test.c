#include "test.h"

/* A consistent final size is accepted; data at or beyond it is rejected. */
static void test_finalsize_data(void) {
  quic_finalsize f;
  quic_finalsize_init(&f);
  CHECK(quic_finalsize_data(&f, 0, 10) == 1); /* data [0,10) */
  CHECK(quic_finalsize_set(&f, 10) == 1);     /* final size 10 matches */
  CHECK(quic_finalsize_data(&f, 0, 10) == 1); /* still within */
  CHECK(quic_finalsize_data(&f, 5, 10) == 0); /* reaches 15 > 10: violation */
}

/* The final size is immutable; a different value is a FINAL_SIZE_ERROR. */
static void test_finalsize_immutable(void) {
  quic_finalsize f;
  quic_finalsize_init(&f);
  CHECK(quic_finalsize_set(&f, 20) == 1);
  CHECK(quic_finalsize_set(&f, 20) == 1); /* same value ok */
  CHECK(quic_finalsize_set(&f, 21) == 0); /* changed: violation */
}

/* A final size below data already seen is a violation. */
static void test_finalsize_below_highest(void) {
  quic_finalsize f;
  quic_finalsize_init(&f);
  CHECK(quic_finalsize_data(&f, 0, 30) == 1); /* highest now 30 */
  CHECK(quic_finalsize_set(&f, 25) == 0);     /* below 30: violation */
  CHECK(quic_finalsize_set(&f, 30) == 1);     /* exactly the highest: ok */
}

/* RFC 9000 4.4: RESET_STREAM terminates only one direction of a bidirectional
 * stream; the unterminated direction's flow control state keeps working.
 * quic_dual_finalsize holds one quic_finalsize per direction so resetting
 * one never touches the other. */
static void test_dual_finalsize_direction_independent_after_reset(void) {
  quic_dual_finalsize df;
  quic_dual_finalsize_init(&df);

  /* receive direction has buffered data in flight */
  CHECK(quic_finalsize_data(&df.recv, 0, 50) == 1);

  /* send direction is reset (final size fixed at 10) */
  CHECK(quic_dual_finalsize_reset_send(&df, 10) == 1);

  /* the receive direction is untouched: still open, still accepts data past
   * where the send direction's reset happened, no final size imposed on it */
  CHECK(df.recv.known == 0);
  CHECK(quic_finalsize_data(&df.recv, 50, 20) == 1); /* now at 70 */
  CHECK(quic_finalsize_set(&df.recv, 70) == 1);      /* consistent */

  /* the send direction's final size is unaffected by the receive side's
   * activity */
  CHECK(df.send.final_size == 10);
  CHECK(df.send.known == 1);
}

/* Resetting the receive direction symmetrically leaves the send direction
 * alone. */
static void test_dual_finalsize_recv_reset_leaves_send_alone(void) {
  quic_dual_finalsize df;
  quic_dual_finalsize_init(&df);

  CHECK(quic_finalsize_data(&df.send, 0, 5) == 1);
  CHECK(quic_dual_finalsize_reset_recv(&df, 30) == 1);

  CHECK(df.send.known == 0);
  CHECK(df.recv.final_size == 30 && df.recv.known == 1);
}

/* A conflicting reset on an already-fixed direction is FINAL_SIZE_ERROR,
 * same as the underlying quic_finalsize_set. */
static void test_dual_finalsize_reset_conflict(void) {
  quic_dual_finalsize df;
  quic_dual_finalsize_init(&df);
  CHECK(quic_dual_finalsize_reset_send(&df, 10) == 1);
  CHECK(quic_dual_finalsize_reset_send(&df, 11) == 0); /* conflicting reset */
}

void test_finalsize(void) {
  test_finalsize_data();
  test_finalsize_immutable();
  test_finalsize_below_highest();
  test_dual_finalsize_direction_independent_after_reset();
  test_dual_finalsize_recv_reset_leaves_send_alone();
  test_dual_finalsize_reset_conflict();
}
