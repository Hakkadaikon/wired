#include "test.h"

/* keq compares len bytes against a hex string. */
static int keq(const u8* got, const char* hex, usz len) {
  for (usz i = 0; i < len; i++) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    u8 b = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                (lo <= '9' ? lo - '0' : lo - 'a' + 10));
    if (got[i] != b) return 0;
  }
  return 1;
}

/* RFC 9001 Appendix A.1: DCID 0x8394c8f03e515708. */
static void test_initial_client(void) {
  const u8          dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_keys k;
  quic_initial_derive(quic_span_of(dcid, 8), 0, &k);
  CHECK(keq(k.key, "1f369613dd76d5467730efcbe3b1a22d", 16));
  CHECK(keq(k.iv, "fa044b2f42a3fd3b46fb255c", 12));
  CHECK(keq(k.hp, "9f50449e04a0e810283a1e9933adedd2", 16));
}

static void test_initial_server(void) {
  const u8          dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_keys k;
  quic_initial_derive(quic_span_of(dcid, 8), 1, &k);
  CHECK(keq(k.key, "cf3a5331653c364c88f0f379b6067e37", 16));
  CHECK(keq(k.iv, "0ac1493ca1905853b0bba03e", 12));
  CHECK(keq(k.hp, "c206b8d9b9f0f37644430b490eeaa314", 16));
}

void test_initial(void) {
  test_initial_client();
  test_initial_server();
}
