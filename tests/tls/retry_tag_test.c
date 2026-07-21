#include "test.h"

/* A generated Retry tag verifies; tampering the pseudo-packet breaks it. */
static void test_retry_tag_roundtrip(void) {
  const u8 odcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  u8       retry[32];
  for (usz i = 0; i < sizeof(retry); i++) retry[i] = (u8)(0xf0 + i);

  u8 tag[QUIC_RETRY_TAG];
  quic_retry_tag(
      quic_span_of(odcid, 8), quic_span_of(retry, sizeof(retry)), tag);

  /* assemble the full Retry packet (retry || tag) and verify */
  u8 full[32 + QUIC_RETRY_TAG];
  for (usz i = 0; i < sizeof(retry); i++) full[i] = retry[i];
  for (usz i = 0; i < QUIC_RETRY_TAG; i++) full[sizeof(retry) + i] = tag[i];
  CHECK(
      quic_retry_verify(
          quic_span_of(odcid, 8), quic_span_of(full, sizeof(full))) == 1);

  /* flip one Retry byte: verification must fail */
  full[3] ^= 0x01;
  CHECK(
      quic_retry_verify(
          quic_span_of(odcid, 8), quic_span_of(full, sizeof(full))) == 0);
  full[3] ^= 0x01;
  /* flip an ODCID byte: verification must fail */
  u8 bad_odcid[8];
  for (usz i = 0; i < 8; i++) bad_odcid[i] = odcid[i];
  bad_odcid[0] ^= 0x80;
  CHECK(
      quic_retry_verify(
          quic_span_of(bad_odcid, 8), quic_span_of(full, sizeof(full))) == 0);
}

/* The tag is deterministic for the same inputs. */
static void test_retry_tag_deterministic(void) {
  const u8 odcid[4]  = {1, 2, 3, 4};
  const u8 retry[10] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
  u8       a[QUIC_RETRY_TAG], b[QUIC_RETRY_TAG];
  quic_retry_tag(quic_span_of(odcid, 4), quic_span_of(retry, 10), a);
  quic_retry_tag(quic_span_of(odcid, 4), quic_span_of(retry, 10), b);
  for (usz i = 0; i < QUIC_RETRY_TAG; i++) CHECK(a[i] == b[i]);
}

/* Boundary ODCID lengths (empty and the 20-byte maximum) still verify, and
 * tampering the tag itself is rejected. */
static void test_retry_tag_boundaries(void) {
  const u8 retry[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  u8       full[12 + QUIC_RETRY_TAG], tag[QUIC_RETRY_TAG];

  /* empty ODCID */
  quic_retry_tag(quic_span_of(0, 0), quic_span_of(retry, 12), tag);
  for (usz i = 0; i < 12; i++) full[i] = retry[i];
  for (usz i = 0; i < QUIC_RETRY_TAG; i++) full[12 + i] = tag[i];
  CHECK(
      quic_retry_verify(quic_span_of(0, 0), quic_span_of(full, sizeof(full))) ==
      1);
  /* flip the last tag byte: rejected */
  full[sizeof(full) - 1] ^= 0x01;
  CHECK(
      quic_retry_verify(quic_span_of(0, 0), quic_span_of(full, sizeof(full))) ==
      0);

  /* maximum 20-byte ODCID */
  u8 odcid[20];
  for (usz i = 0; i < 20; i++) odcid[i] = (u8)(i + 1);
  quic_retry_tag(quic_span_of(odcid, 20), quic_span_of(retry, 12), tag);
  for (usz i = 0; i < QUIC_RETRY_TAG; i++) full[12 + i] = tag[i];
  CHECK(
      quic_retry_verify(
          quic_span_of(odcid, 20), quic_span_of(full, sizeof(full))) == 1);
}

/* RFC 9001 A.4: the official Retry vector. ODCID 8394c8f03e515708; the
 * Retry packet ff000000 0100 08f0 67a5 502a 4262 b574 6f6b 656e carries
 * token "token" and must produce exactly the appendix's integrity tag. */
static void test_retry_tag_rfc9001_a4_vector(void) {
  const u8 odcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  const u8 retry[]  = {0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08,
                       0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
                       0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e};
  const u8 want[16] = {0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82,
                       0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba};
  u8       tag[QUIC_RETRY_TAG];
  quic_retry_tag(
      quic_span_of(odcid, 8), quic_span_of(retry, sizeof retry), tag);
  for (usz i = 0; i < 16; i++) CHECK(tag[i] == want[i]);
}

void test_retry_tag(void) {
  test_retry_tag_roundtrip();
  test_retry_tag_deterministic();
  test_retry_tag_boundaries();
  test_retry_tag_rfc9001_a4_vector();
}
