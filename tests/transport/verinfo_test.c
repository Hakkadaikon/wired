#include "test.h"
#include "transport/version/version/version.h"

/* RFC 9368 3: encode then decode reproduces Chosen + Available. */
static void test_verinfo_roundtrip(void) {
  version_information in = {
      QUIC_VERSION_1, 2, {QUIC_VERSION_1, QUIC_VERSION_2}};
  u8  buf[64];
  usz n = verinfo_encode(buf, sizeof buf, &in);
  CHECK(n == 4 + 4 * 2);

  version_information out;
  CHECK(verinfo_decode(buf, n, &out) == n);
  CHECK(out.chosen == QUIC_VERSION_1);
  CHECK(out.count == 2);
  CHECK(out.available[0] == QUIC_VERSION_1);
  CHECK(out.available[1] == QUIC_VERSION_2);
}

/* Wire bytes are 4 big-endian bytes per version. */
static void test_verinfo_wire_be(void) {
  version_information in = {QUIC_VERSION_1, 1, {QUIC_VERSION_2}};
  u8                  buf[8];
  CHECK(verinfo_encode(buf, sizeof buf, &in) == 8);
  CHECK(buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 1);
  CHECK(buf[4] == 0x6b && buf[5] == 0x33 && buf[6] == 0x43 && buf[7] == 0xcf);
}

/* Chosen Version with an empty Available Versions list is well-formed. */
static void test_verinfo_chosen_only(void) {
  version_information in = {QUIC_VERSION_2, 0, {0}};
  u8                  buf[8];
  usz                 n = verinfo_encode(buf, sizeof buf, &in);
  CHECK(n == 4);
  version_information out;
  CHECK(verinfo_decode(buf, n, &out) == 4);
  CHECK(out.chosen == QUIC_VERSION_2 && out.count == 0);
}

/* Encode fails when the buffer cannot hold the value. */
static void test_verinfo_encode_no_room(void) {
  version_information in = {QUIC_VERSION_1, 1, {QUIC_VERSION_2}};
  u8                  buf[7];
  CHECK(verinfo_encode(buf, sizeof buf, &in) == 0);
}

/* Decode rejects truncated and misaligned lengths. */
static void test_verinfo_decode_bad(void) {
  u8 buf[8] = {0};
  CHECK(verinfo_decode(buf, 0, (version_information[]){{0}}) == 0);
  CHECK(verinfo_decode(buf, 3, (version_information[]){{0}}) == 0);
  CHECK(verinfo_decode(buf, 6, (version_information[]){{0}}) == 0);
}

void test_verinfo(void) {
  test_verinfo_roundtrip();
  test_verinfo_wire_be();
  test_verinfo_chosen_only();
  test_verinfo_encode_no_room();
  test_verinfo_decode_bad();
}
