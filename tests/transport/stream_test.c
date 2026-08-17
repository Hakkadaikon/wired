#include "test.h"

/* Happy path: Ready -> Send -> Data Sent -> Data Recvd. */
static void test_send_happy(void) {
  send_state s = SEND_READY;
  CHECK(send_step(&s, SEND_EV_STREAM) && s == SEND_SEND);
  CHECK(send_step(&s, SEND_EV_FIN_SENT) && s == SEND_DATA_SENT);
  CHECK(send_step(&s, SEND_EV_ACKED) && s == SEND_DATA_RECVD);
}

/* Reset path and that terminal states reject further events. */
static void test_send_reset_and_terminal(void) {
  send_state s = SEND_SEND;
  CHECK(send_step(&s, SEND_EV_RESET) && s == SEND_RESET_SENT);
  CHECK(send_step(&s, SEND_EV_RESET_ACKED) && s == SEND_RESET_RECVD);
  /* terminal: no event is valid */
  CHECK(!send_step(&s, SEND_EV_RESET) && s == SEND_RESET_RECVD);

  send_state d = SEND_DATA_RECVD;
  CHECK(!send_step(&d, SEND_EV_ACKED) && d == SEND_DATA_RECVD);
  /* reset and normal completion are mutually exclusive: a completed
   * sending stream must not accept RESET (stream_send_no_reset_after_complete)
   */
  CHECK(!send_step(&d, SEND_EV_RESET) && d == SEND_DATA_RECVD);
}

/* A fully received stream must not transition to ResetRecvd
 * (stream_recv_no_reset_after_complete). */
static void test_recv_no_reset_after_complete(void) {
  recv_state r = RECV_DATA_RECVD;
  CHECK(!recv_step(&r, RECV_EV_RESET) && r == RECV_DATA_RECVD);
  recv_state d = RECV_DATA_READ;
  CHECK(!recv_step(&d, RECV_EV_RESET) && d == RECV_DATA_READ);
}

/* Illegal transitions are rejected and leave the state untouched. */
static void test_send_illegal(void) {
  send_state s = SEND_READY;
  /* cannot ACK before anything was sent */
  CHECK(!send_step(&s, SEND_EV_ACKED) && s == SEND_READY);
  /* cannot go Ready -> Data Sent directly */
  CHECK(!send_step(&s, SEND_EV_FIN_SENT) && s == SEND_READY);
}

static void test_recv_happy(void) {
  recv_state r = RECV_RECV;
  CHECK(recv_step(&r, RECV_EV_FIN) && r == RECV_SIZE_KNOWN);
  CHECK(recv_step(&r, RECV_EV_ALL_DATA) && r == RECV_DATA_RECVD);
  CHECK(recv_step(&r, RECV_EV_READ) && r == RECV_DATA_READ);
}

static void test_recv_reset_and_illegal(void) {
  recv_state r = RECV_RECV;
  CHECK(recv_step(&r, RECV_EV_RESET) && r == RECV_RESET_RECVD);
  CHECK(recv_step(&r, RECV_EV_READ) && r == RECV_RESET_READ);
  /* once all data is read, no further event applies */
  CHECK(!recv_step(&r, RECV_EV_RESET) && r == RECV_RESET_READ);
  /* cannot read before size is known */
  recv_state q = RECV_RECV;
  CHECK(!recv_step(&q, RECV_EV_READ) && q == RECV_RECV);
}

void test_stream(void) {
  test_send_happy();
  test_send_reset_and_terminal();
  test_send_illegal();
  test_recv_happy();
  test_recv_reset_and_illegal();
  test_recv_no_reset_after_complete();
}
