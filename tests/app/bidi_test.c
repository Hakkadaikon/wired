#include "test.h"

/* A bidirectional stream is closed only when both halves are terminal. */
static void test_bidi_closed(void) {
  bidi b;
  bidi_init(&b);
  CHECK(bidi_closed(&b) == 0); /* both fresh */

  b.send = QUIC_SEND_DATA_RECVD; /* send terminal */
  CHECK(bidi_closed(&b) == 0);   /* recv still open */

  b.recv = QUIC_RECV_DATA_READ; /* recv terminal too */
  CHECK(bidi_closed(&b) == 1);

  /* reset on either half is also terminal */
  bidi_init(&b);
  b.send = QUIC_SEND_RESET_RECVD;
  b.recv = QUIC_RECV_RESET_READ;
  CHECK(bidi_closed(&b) == 1);

  /* a non-terminal send keeps it open */
  b.send = QUIC_SEND_DATA_SENT;
  CHECK(bidi_closed(&b) == 0);
}

void test_bidi(void) { test_bidi_closed(); }
