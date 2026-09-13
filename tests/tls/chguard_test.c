#include "test.h"

/* Write one type(2)+len(2)+data TLV at buf+off; returns the new offset. */
static usz chg_put_tlv(u8* buf, usz off, unsigned type, const u8* data, usz n) {
  buf[off]     = (u8)(type >> 8);
  buf[off + 1] = (u8)type;
  buf[off + 2] = (u8)(n >> 8);
  buf[off + 3] = (u8)n;
  for (usz i = 0; i < n; i++) buf[off + 4 + i] = data[i];
  return off + 4 + n;
}

/* RFC 8446 4.2: "There MUST NOT be more than one extension of the same
 * type in a given extension block." Two distinct types pass; a repeated
 * type is rejected. */
static void test_chguard_rejects_duplicate_extension(void) {
  u8  buf[64];
  u8  d1[2] = {0xaa, 0xbb}, d2[1] = {0x01}, d3[1] = {0x02};
  usz w = 0;
  w     = chg_put_tlv(buf, w, 0x000a /* supported_groups */, d1, 2);
  w     = chg_put_tlv(buf, w, 0x000d /* signature_algorithms */, d2, 1);
  CHECK(chguard_no_dup_ext(wired_span_of(buf, w)) == 1);

  usz w2 = chg_put_tlv(buf, w, 0x000a /* repeats the first type */, d3, 1);
  CHECK(chguard_no_dup_ext(wired_span_of(buf, w2)) == 0);
}

/* A TLV whose declared data length overruns the buffer is malformed and
 * rejected outright, distinct from the duplicate-type check above. */
static void test_chguard_rejects_malformed_tlv(void) {
  u8 buf[8];
  buf[0] = 0x00;
  buf[1] = 0x0a;
  buf[2] = 0x00;
  buf[3] = 0x05; /* declares 5 bytes of data */
  buf[4] = 0x01; /* only 2 bytes follow: truncated */
  buf[5] = 0x02;
  CHECK(chguard_no_dup_ext(wired_span_of(buf, 6)) == 0);
  CHECK(chguard_ch_legal_exts(wired_span_of(buf, 6)) == 0);
}

/* RFC 8446 4.2: an extension_type this SDK recognizes but that is not
 * specified for ClientHello (oid_filters, 48) is CH-illegal; every other
 * recognized type is ignored (never rejected here). */
static void test_chguard_rejects_oid_filters_in_ch(void) {
  u8  buf[32];
  u8  d1[2] = {0xaa, 0xbb};
  usz w     = chg_put_tlv(buf, 0, 0x000a /* supported_groups */, d1, 2);
  CHECK(chguard_ch_legal_exts(wired_span_of(buf, w)) == 1);

  usz w2 =
      chg_put_tlv(buf, w, 48 /* oid_filters: CertificateRequest-only */, d1, 2);
  CHECK(chguard_ch_legal_exts(wired_span_of(buf, w2)) == 0);
}

/* An extension_type this SDK does not special-case is skipped by its
 * declared length rather than rejected (RFC 8446 4.2/4.1.2's "ignore
 * unknown extensions"). */
static void test_chguard_unknown_ext_ignored(void) {
  u8  buf[32];
  u8  d1[3] = {1, 2, 3};
  usz w     = chg_put_tlv(buf, 0, 0x1234 /* unassigned type */, d1, 3);
  CHECK(chguard_ch_legal_exts(wired_span_of(buf, w)) == 1);
  CHECK(chguard_no_dup_ext(wired_span_of(buf, w)) == 1);
}

void test_chguard(void) {
  test_chguard_rejects_duplicate_extension();
  test_chguard_rejects_malformed_tlv();
  test_chguard_rejects_oid_filters_in_ch();
  test_chguard_unknown_ext_ignored();
}
