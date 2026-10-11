#include "app/qpack/qpackdyn/dec_stream.h"
#include "common/bytes/util/ct.h"
#include "test.h"

/* 1 if d's pending decoder-stream bytes for `inserts` are exactly want. */
static int ds_pending_is(
    const qdyn_dec* d, u64 inserts, const u8* want, usz n) {
  u8         b[QDYN_DEC_OUT_MAX];
  wired_obuf ob = {b, sizeof b, 0};
  return qdyn_dec_pending(d, inserts, &ob) == n && ob.len == n &&
         ct_diffn(b, want, n) == 0;
}

/* RFC 9204 Appendix B.2-B.5's decoder stream: Section Acknowledgment for
 * stream 4 (which also covers B.2's two inserts, so no Insert Count
 * Increment), Insert Count Increment 1 after B.3's speculative insert,
 * Section Acknowledgment for stream 8 after B.4 (this decoder had the
 * encoder data, so it acknowledges instead of B.4's cancellation), then
 * Insert Count Increment 1 after B.5. */
static void test_dec_stream_appendix_b(void) {
  static const u8 b2[] = {0x84}, b3[] = {0x01}, b4[] = {0x88};
  qdyn_dec        d = {0};
  qdyn_dec_section_ack(&d, 4, 2);
  CHECK(ds_pending_is(&d, 2, b2, 1));
  qdyn_dec_sent(&d, 2);
  CHECK(ds_pending_is(&d, 2, 0, 0));
  CHECK(ds_pending_is(&d, 3, b3, 1));
  qdyn_dec_sent(&d, 3);
  qdyn_dec_section_ack(&d, 8, 4);
  CHECK(ds_pending_is(&d, 4, b4, 1));
  qdyn_dec_sent(&d, 4);
  CHECK(ds_pending_is(&d, 5, b3, 1));
}

/* RFC 9204 4.4.1 / 4.4.3: a section with Required Insert Count 0 is never
 * acknowledged; acknowledgments go out before the increment, which then
 * counts only inserts no acknowledgment covered. */
static void test_dec_stream_ack_then_increment(void) {
  static const u8 want[] = {0x84, 0x01};
  qdyn_dec        d      = {0};
  qdyn_dec_section_ack(&d, 0x10, 0);
  CHECK(ds_pending_is(&d, 0, 0, 0));
  qdyn_dec_section_ack(&d, 4, 2);
  CHECK(ds_pending_is(&d, 3, want, 2));
  CHECK(ds_pending_is(&d, 3, want, 2)); /* pending does not consume */
}

void test_qpackdyn_dec_stream(void) {
  test_dec_stream_appendix_b();
  test_dec_stream_ack_then_increment();
}
