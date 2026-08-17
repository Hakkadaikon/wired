#include "test.h"

static const u8 H3[2]   = {0x68, 0x33};       /* "h3" */
static const u8 SPDY[3] = {0x68, 0x71, 0x39}; /* "hq9", unknown */

/* RFC 9001 8.1: a selected ALPN is required for the QUIC handshake. */
static void test_alpnver_require(void) {
  CHECK(alpnver_require(H3, sizeof H3) == 1);
  CHECK(alpnver_require(0, 0) == 0);  /* none selected */
  CHECK(alpnver_require(H3, 0) == 0); /* empty selection */
}

/* RFC 7301 3.2 / RFC 9114: classify the selected protocol name. */
static void test_alpnver_protocol(void) {
  CHECK(alpnver_protocol(H3, sizeof H3) == QUIC_ALPNVER_PROTO_H3);
  CHECK(alpnver_protocol(SPDY, sizeof SPDY) == QUIC_ALPNVER_PROTO_NONE);
  CHECK(alpnver_protocol(H3, 0) == QUIC_ALPNVER_PROTO_NONE);
}

/* RFC 9368 / RFC 9000 7.4: h3 stays valid across compatible versions. */
static void test_alpnver_compatible(void) {
  CHECK(alpnver_compatible(QUIC_VERSION_1, H3, sizeof H3) == 1);
  CHECK(alpnver_compatible(QUIC_VERSION_2, H3, sizeof H3) == 1);
  CHECK(alpnver_compatible(0xdeadbeef, H3, sizeof H3) == 0); /* unknown ver */
  CHECK(alpnver_compatible(QUIC_VERSION_1, SPDY, sizeof SPDY) == 0);
}

void test_alpnver(void) {
  test_alpnver_require();
  test_alpnver_protocol();
  test_alpnver_compatible();
}
