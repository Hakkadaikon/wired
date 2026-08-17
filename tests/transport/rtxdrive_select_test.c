#include "test.h"

/* RFC 9002 13.3: a held STREAM frame is selected for retransmission, an
 * ACK frame is not, an unknown pn is not held. */
static void test_select_stream_retransmittable(void) {
  rtxbytes st;
  const u8 s1[] = {0x08, 0x00, 0x02, 'h', 'i'};
  int      rtx  = -1;

  rtxbytes_init(&st);
  rtxbytes_store(&st, 10, wired_span_of(s1, sizeof s1));

  CHECK(rtxdrive_select(&st, 10, &rtx) == 1);
  CHECK(rtx == 1);
}

/* RFC 9000 13.3: a held HANDSHAKE_DONE (0x1e) is selected for retransmission
 * like any other ack-eliciting frame, until it is acknowledged. */
static void test_select_handshake_done_retransmittable(void) {
  rtxbytes st;
  const u8 hs_done[] = {0x1e};
  int      rtx       = -1;

  rtxbytes_init(&st);
  rtxbytes_store(&st, 12, wired_span_of(hs_done, sizeof hs_done));

  CHECK(rtxdrive_select(&st, 12, &rtx) == 1);
  CHECK(rtx == 1);
}

static void test_select_ack_not_retransmittable(void) {
  rtxbytes st;
  const u8 ack[] = {0x02, 0x00, 0x00, 0x00};
  int      rtx   = -1;

  rtxbytes_init(&st);
  rtxbytes_store(&st, 11, wired_span_of(ack, sizeof ack));

  CHECK(rtxdrive_select(&st, 11, &rtx) == 1);
  CHECK(rtx == 0);
}

static void test_select_pn_not_held(void) {
  rtxbytes st;
  int      rtx = -1;

  rtxbytes_init(&st);
  CHECK(rtxdrive_select(&st, 99, &rtx) == 0);
}

void test_rtxdrive_select(void) {
  test_select_stream_retransmittable();
  test_select_handshake_done_retransmittable();
  test_select_ack_not_retransmittable();
  test_select_pn_not_held();
}
