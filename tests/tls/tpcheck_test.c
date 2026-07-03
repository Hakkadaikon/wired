#include "test.h"

/* RFC 9000 7.3 / 18.2: connection-ID transport parameters are authenticated
 * against the connection IDs observed on the wire. */
void test_tpcheck(void) {
  static const u8 a[] = {0x01, 0x02, 0x03, 0x04};
  static const u8 b[] = {0x01, 0x02, 0x03, 0x04};
  static const u8 c[] = {0x01, 0x02, 0x03, 0x05}; /* differs in last byte */
  static const u8 z[] = {0};

  quic_span sa   = quic_span_of(a, 4);
  quic_span sb   = quic_span_of(b, 4);
  quic_span sc   = quic_span_of(c, 4);
  quic_span sz   = quic_span_of(z, 0);
  quic_span none = quic_span_of(0, 0);

  /* byte-for-byte match, including length */
  CHECK(quic_tparam_cid_match(sa, sb) == 1);
  CHECK(quic_tparam_cid_match(sa, sc) == 0);
  CHECK(
      quic_tparam_cid_match(sa, quic_span_of(a, 3)) == 0); /* length mismatch */
  CHECK(quic_tparam_cid_match(sz, sz) == 1); /* both empty (zero-length CID) */

  /* initial_source_connection_id vs the peer's observed Source CID */
  CHECK(quic_tparam_check_initial_scid(sa, sb) == 1);
  CHECK(quic_tparam_check_initial_scid(sa, sc) == 0);

  /* original_destination_connection_id vs the DCID the client sent */
  CHECK(quic_tparam_check_original_dcid(sa, sb) == 1);
  CHECK(quic_tparam_check_original_dcid(sa, sc) == 0);

  /* retry_source_connection_id: present iff a Retry was processed */
  CHECK(
      quic_tparam_check_retry_scid(&(quic_tparam_retry_scid_in){
          1, 1, sa, sb}) == 1); /* retry, matches */
  CHECK(
      quic_tparam_check_retry_scid(&(quic_tparam_retry_scid_in){
          1, 1, sa, sc}) == 0); /* retry, mismatch */
  CHECK(
      quic_tparam_check_retry_scid(&(quic_tparam_retry_scid_in){
          1, 0, none, sb}) == 0); /* retry but missing */
  CHECK(
      quic_tparam_check_retry_scid(&(quic_tparam_retry_scid_in){
          0, 1, sa, none}) == 0); /* present but no retry */
  CHECK(
      quic_tparam_check_retry_scid(&(quic_tparam_retry_scid_in){
          0, 0, none, none}) == 1); /* no retry, absent */
}
