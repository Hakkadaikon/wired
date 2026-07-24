#include "app/qpack/qpack/insertcount.h"

#include "test.h"

/* RFC 9204 4.5.1.1: a Required Insert Count of 0 encodes to 0 and decodes back
 * to 0 regardless of MaxEntries or inserts. */
static void test_qpack_ric_zero(void) {
  CHECK(quic_qpack_ric_encode(0, 3) == 0);
  u64                ric = 99;
  quic_qpack_ric_ctx c   = {3, 0};
  CHECK(quic_qpack_ric_decode(0, &c, &ric) == 1 && ric == 0);
}

/* RFC 9204 4.5.1.1 worked example: MaxEntries 3, 10 total inserts, RIC 9
 * encodes to 4 and decodes back to 9. */
static void test_qpack_ric_example(void) {
  CHECK(quic_qpack_ric_encode(9, 3) == 4);
  u64                ric = 0;
  quic_qpack_ric_ctx c   = {3, 10};
  CHECK(quic_qpack_ric_decode(4, &c, &ric) == 1 && ric == 9);
}

/* RFC 9204 4.5.1.1: EncodedInsertCount above 2*MaxEntries is invalid, and a
 * non-zero encoding that resolves to RIC 0 is rejected. */
static void test_qpack_ric_invalid(void) {
  u64                ric = 0;
  quic_qpack_ric_ctx c   = {3, 10};
  CHECK(quic_qpack_ric_decode(7, &c, &ric) == 0);
  /* encoded 1 with no inserts wraps to candidate 0, which is invalid. */
  quic_qpack_ric_ctx empty = {3, 0};
  CHECK(quic_qpack_ric_decode(1, &empty, &ric) == 0);
}

/* Round-trip across the wrap boundary: every RIC up to one full range decodes
 * back to itself when TotalNumberOfInserts equals RIC (RFC 9204 4.5.1.1). */
static void test_qpack_ric_roundtrip(void) {
  u64 max_entries = 4;
  for (u64 r = 1; r <= 2 * max_entries; r++) {
    u64                enc = quic_qpack_ric_encode(r, max_entries);
    u64                ric = 0;
    quic_qpack_ric_ctx c   = {max_entries, r};
    CHECK(quic_qpack_ric_decode(enc, &c, &ric) == 1);
    CHECK(ric == r);
  }
}

/* RFC 9204 2.1.2 / 2.2.1: with no dynamic table reference the expected
 * minimum RIC is 0; a section carrying RIC 0 is accepted. */
static void test_qpack_ric_min_no_dynamic_ref(void) {
  CHECK(quic_qpack_ric_min_ok(0, 0, 0));
}

/* RFC 9204 2.1.2: with a dynamic reference, the lowest valid RIC is one more
 * than the largest referenced absolute index; a RIC below that is rejected. */
static void test_qpack_ric_min_below_expected_rejected(void) {
  CHECK(!quic_qpack_ric_min_ok(3, 1, 3)); /* expected 4, got 3 */
  CHECK(!quic_qpack_ric_min_ok(0, 1, 0)); /* expected 1, got 0 */
}

/* RFC 9204 2.2.1: a RIC exactly equal to the expected minimum is accepted. */
static void test_qpack_ric_min_exact_accepted(void) {
  CHECK(quic_qpack_ric_min_ok(4, 1, 3));
  CHECK(quic_qpack_ric_min_ok(1, 1, 0));
}

/* RFC 9204 2.2.1: a RIC larger than expected is not the MUST-reject case
 * covered here (the spec only permits, does not require, rejecting it). */
static void test_qpack_ric_min_above_expected_accepted(void) {
  CHECK(quic_qpack_ric_min_ok(9, 1, 3));
}

/* RFC 9204 4.4.3: an Increment of zero is always invalid, regardless of the
 * current Known Received Count or how many inserts the encoder has sent. */
static void test_qpack_incr_zero_rejected(void) {
  CHECK(!quic_qpack_incr_valid(0, 0, 5));
  CHECK(!quic_qpack_incr_valid(2, 0, 5));
}

/* RFC 9204 Appendix B.3: Known Received Count 2, Increment 1, and the encoder
 * has sent 3 insertions -- the increment exactly catches up and is valid. */
static void test_qpack_incr_golden(void) {
  CHECK(quic_qpack_incr_valid(2, 1, 3));
}

/* RFC 9204 4.4.3: an Increment that would raise the Known Received Count
 * beyond total_inserts (what the encoder actually sent) is invalid. */
static void test_qpack_incr_overshoot_rejected(void) {
  CHECK(!quic_qpack_incr_valid(2, 2, 3)); /* would reach 4, only 3 sent */
}

/* An increment landing exactly on total_inserts is the accepted boundary. */
static void test_qpack_incr_exact_boundary_accepted(void) {
  CHECK(quic_qpack_incr_valid(0, 3, 3));
}

/* RFC 9204 4.4.1: a Section Acknowledgment is valid exactly while the
 * stream it names has at least one unacknowledged field section (non-zero
 * Required Insert Count) outstanding. */
static void test_qpack_section_ack_pending_accepted(void) {
  CHECK(quic_qpack_section_ack_valid(1));
  CHECK(quic_qpack_section_ack_valid(5));
}

/* RFC 9204 4.4.1: "If an encoder receives a Section Acknowledgment
 * instruction referring to a stream on which every encoded field section
 * with a non-zero Required Insert Count has already been acknowledged,
 * this MUST be treated as a connection error of type
 * QPACK_DECODER_STREAM_ERROR." pending_acks == 0 is exactly that state. */
static void test_qpack_section_ack_none_pending_rejected(void) {
  CHECK(!quic_qpack_section_ack_valid(0));
}

void test_insertcount(void) {
  test_qpack_ric_zero();
  test_qpack_ric_example();
  test_qpack_ric_invalid();
  test_qpack_ric_roundtrip();
  test_qpack_ric_min_no_dynamic_ref();
  test_qpack_ric_min_below_expected_rejected();
  test_qpack_ric_min_exact_accepted();
  test_qpack_ric_min_above_expected_accepted();
  test_qpack_incr_zero_rejected();
  test_qpack_incr_golden();
  test_qpack_incr_overshoot_rejected();
  test_qpack_incr_exact_boundary_accepted();
  test_qpack_section_ack_pending_accepted();
  test_qpack_section_ack_none_pending_rejected();
}
