#include "test.h"

/* RFC 9000 7.3 / 18.2: connection-ID transport parameters are authenticated
 * against the connection IDs observed on the wire. */
void test_tpcheck(void) {
  static const u8 a[] = {0x01, 0x02, 0x03, 0x04};
  static const u8 b[] = {0x01, 0x02, 0x03, 0x04};
  static const u8 c[] = {0x01, 0x02, 0x03, 0x05}; /* differs in last byte */
  static const u8 z[] = {0};

  wired_span sa   = wired_span_of(a, 4);
  wired_span sb   = wired_span_of(b, 4);
  wired_span sc   = wired_span_of(c, 4);
  wired_span sz   = wired_span_of(z, 0);
  wired_span none = wired_span_of(0, 0);

  /* byte-for-byte match, including length */
  CHECK(quic_tparam_cid_match(sa, sb) == 1);
  CHECK(quic_tparam_cid_match(sa, sc) == 0);
  CHECK(
      quic_tparam_cid_match(sa, wired_span_of(a, 3)) ==
      0);                                    /* length mismatch */
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

/* RFC 9000 18.2: an endpoint MUST treat receipt of a transport parameter
 * with an invalid value as a connection error of type
 * TRANSPORT_PARAMETER_ERROR. Boundary values for the four range-constrained
 * integer parameters. */
void test_tparam_range_ok(void) {
  /* max_udp_payload_size: "Values below 1200 are invalid." */
  CHECK(quic_tparam_range_ok(QUIC_TP_MAX_UDP_PAYLOAD_SIZE, 1200) == 1);
  CHECK(quic_tparam_range_ok(QUIC_TP_MAX_UDP_PAYLOAD_SIZE, 1199) == 0);
  CHECK(quic_tparam_range_ok(QUIC_TP_MAX_UDP_PAYLOAD_SIZE, 65527) == 1);

  /* ack_delay_exponent: "Values above 20 are invalid." */
  CHECK(quic_tparam_range_ok(QUIC_TP_ACK_DELAY_EXPONENT, 20) == 1);
  CHECK(quic_tparam_range_ok(QUIC_TP_ACK_DELAY_EXPONENT, 21) == 0);
  CHECK(quic_tparam_range_ok(QUIC_TP_ACK_DELAY_EXPONENT, 0) == 1);

  /* max_ack_delay: "Values of 2^14 or greater are invalid." */
  CHECK(quic_tparam_range_ok(QUIC_TP_MAX_ACK_DELAY, 16383) == 1);
  CHECK(quic_tparam_range_ok(QUIC_TP_MAX_ACK_DELAY, 16384) == 0);
  CHECK(quic_tparam_range_ok(QUIC_TP_MAX_ACK_DELAY, 0) == 1);

  /* active_connection_id_limit: "MUST be at least 2." */
  CHECK(quic_tparam_range_ok(QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, 2) == 1);
  CHECK(quic_tparam_range_ok(QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, 1) == 0);
  CHECK(quic_tparam_range_ok(QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, 0) == 0);

  /* unconstrained parameter ids: always valid regardless of value */
  CHECK(quic_tparam_range_ok(QUIC_TP_INITIAL_MAX_DATA, 0) == 1);
  CHECK(
      quic_tparam_range_ok(QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 0xffffffffull) ==
      1);
}
