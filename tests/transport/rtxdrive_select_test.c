#include "test.h"

/* RFC 9002 13.3: a held STREAM frame is selected for retransmission, an
 * ACK frame is not, an unknown pn is not held. */
static void test_select_stream_retransmittable(void) {
  quic_rtxbytes st;
  const u8      s1[] = {0x08, 0x00, 0x02, 'h', 'i'};
  int           rtx  = -1;

  quic_rtxbytes_init(&st);
  quic_rtxbytes_store(&st, 10, quic_span_of(s1, sizeof s1));

  CHECK(quic_rtxdrive_select(&st, 10, &rtx) == 1);
  CHECK(rtx == 1);
}

static void test_select_ack_not_retransmittable(void) {
  quic_rtxbytes st;
  const u8      ack[] = {0x02, 0x00, 0x00, 0x00};
  int           rtx   = -1;

  quic_rtxbytes_init(&st);
  quic_rtxbytes_store(&st, 11, quic_span_of(ack, sizeof ack));

  CHECK(quic_rtxdrive_select(&st, 11, &rtx) == 1);
  CHECK(rtx == 0);
}

static void test_select_pn_not_held(void) {
  quic_rtxbytes st;
  int           rtx = -1;

  quic_rtxbytes_init(&st);
  CHECK(quic_rtxdrive_select(&st, 99, &rtx) == 0);
}

void test_rtxdrive_select(void) {
  test_select_stream_retransmittable();
  test_select_ack_not_retransmittable();
  test_select_pn_not_held();
}
