#include "test.h"

/* RFC 9002 13.3: several lost packets' retransmittable frames are repackaged
 * into one new packet, in order; ACK/PADDING and unheld pns are skipped. */
static void test_batch_concat(void) {
  quic_rtxbytes st;
  const u8      s1[]   = {0x08, 0x00, 0x02, 'h', 'i'};
  const u8      ack[]  = {0x02, 0x00, 0x00, 0x00};
  const u8      s2[]   = {0x08, 0x04, 0x03, 'b', 'y', 'e'};
  const u64     lost[] = {10, 11, 12, 99};
  u8            out[64];
  usz           out_len = 0;

  quic_rtxbytes_init(&st);
  quic_rtxbytes_store(&st, 10, s1, sizeof s1);
  quic_rtxbytes_store(&st, 11, ack, sizeof ack);
  quic_rtxbytes_store(&st, 12, s2, sizeof s2);

  CHECK(quic_rtxdrive_batch(&st, lost, 4, out, sizeof out, &out_len) == 1);
  CHECK(out_len == sizeof s1 + sizeof s2);
  for (usz i = 0; i < sizeof s1; i++) CHECK(out[i] == s1[i]);
  for (usz i = 0; i < sizeof s2; i++) CHECK(out[sizeof s1 + i] == s2[i]);
}

/* cap holds the first frame but not the second: the batch stops, keeping what
 * fit (RFC 9002 13.3 repackaging is bounded by one packet's room). */
static void test_batch_truncates_on_cap(void) {
  quic_rtxbytes st;
  const u8      s1[]   = {0x08, 0x00, 0x02, 'h', 'i'};
  const u8      s2[]   = {0x08, 0x04, 0x03, 'b', 'y', 'e'};
  const u64     lost[] = {10, 12};
  u8            out[6];
  usz           out_len = 0;

  quic_rtxbytes_init(&st);
  quic_rtxbytes_store(&st, 10, s1, sizeof s1);
  quic_rtxbytes_store(&st, 12, s2, sizeof s2);

  CHECK(quic_rtxdrive_batch(&st, lost, 2, out, sizeof out, &out_len) == 1);
  CHECK(out_len == sizeof s1);
  for (usz i = 0; i < sizeof s1; i++) CHECK(out[i] == s1[i]);
}

static void test_batch_empty_store(void) {
  quic_rtxbytes st;
  const u64     lost[] = {1, 2, 3};
  u8            out[64];
  usz           out_len = 99;

  quic_rtxbytes_init(&st);
  CHECK(quic_rtxdrive_batch(&st, lost, 3, out, sizeof out, &out_len) == 1);
  CHECK(out_len == 0);
}

void test_rtxdrive_batch(void) {
  test_batch_concat();
  test_batch_truncates_on_cap();
  test_batch_empty_store();
}
