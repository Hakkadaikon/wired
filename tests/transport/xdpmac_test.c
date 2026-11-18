#include "transport/io/xdp/xdpmac/xdpmac.h"

#include "test.h"

/* Distinct 16-byte keys fd00::(n+1); a few rotating buffers, so two calls
 * can sit in one expression. */
static const u8* xm_ip(u32 n) {
  static u8  b[4][16];
  static u32 k;
  u8*        p = b[k++ % 4];
  bytes_memset(p, 0, 16);
  p[0] = 0xfd;
  be_put_be32(p + 12, n + 1);
  return p;
}

/* Our address for every test entry. */
static const u8 xm_our[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0,
                              0,    0, 0, 0, 0, 0, 0, 0x99};
static u8       xm_got_our[16];

static void xm_mac(u32 n, u8 out[6]) {
  for (u32 i = 0; i < 6; i++) {
    out[i] = (u8)(n + i);
  }
}

/* learn then lookup returns 1 and the learned MAC. */
static void test_xdpmac_learn_then_lookup(void) {
  xdpmac c;
  u8     mac[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
  u8     got[6] = {0};
  xdpmac_init(&c);
  xdpmac_learn(&c, xm_ip(0), mac, xm_our);
  CHECK(xdpmac_lookup(&c, xm_ip(0), got, xm_got_our) == 1);
  for (u32 i = 0; i < 6; i++) {
    CHECK(got[i] == mac[i]);
  }
}

/* an ip never learned misses (0), and mac_out is untouched. */
static void test_xdpmac_miss(void) {
  xdpmac c;
  u8     got[6] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
  xdpmac_init(&c);
  CHECK(xdpmac_lookup(&c, xm_ip(0), got, xm_got_our) == 0);
  for (u32 i = 0; i < 6; i++) {
    CHECK(got[i] == 0x55);
  }
}

/* re-learning the same ip updates the MAC in place (no second slot). */
static void test_xdpmac_relearn_updates(void) {
  xdpmac c;
  u8     a[6] = {1, 1, 1, 1, 1, 1};
  u8     b[6] = {2, 2, 2, 2, 2, 2};
  u8     got[6];
  xdpmac_init(&c);
  xdpmac_learn(&c, xm_ip(0), a, xm_our);
  xdpmac_learn(&c, xm_ip(0), b, xm_our);
  CHECK(xdpmac_lookup(&c, xm_ip(0), got, xm_got_our) == 1);
  for (u32 i = 0; i < 6; i++) {
    CHECK(got[i] == 2);
  }
}

/* 64 entries fill the cache; the 65th evicts round-robin: the oldest (first
 * learned) is gone, the newest and every other entry are still present. */
static void test_xdpmac_full_evicts_round_robin(void) {
  xdpmac c;
  u8     mac[6];
  u8     got[6];
  xdpmac_init(&c);
  for (u32 n = 0; n < XDPMAC_CAP + 1; n++) {
    xm_mac(n, mac);
    xdpmac_learn(&c, xm_ip(n), mac, xm_our);
  }
  CHECK(xdpmac_lookup(&c, xm_ip(0), got, xm_got_our) == 0); /* oldest evicted */
  CHECK(
      xdpmac_lookup(&c, xm_ip(XDPMAC_CAP), got, xm_got_our) == 1); /* newest */
  CHECK(got[0] == (u8)XDPMAC_CAP);
  for (u32 n = 1; n < XDPMAC_CAP; n++) {
    CHECK(
        xdpmac_lookup(&c, xm_ip(n), got, xm_got_our) ==
        1); /* survivors intact */
  }
}

/* The lookup also returns the address the peer sent to, and a v4-mapped
 * key never matches the IPv6 key with the same last four bytes. */
static void test_xdpmac_our_address_and_family(void) {
  static const u8 v4[16]   = {0, 0, 0,    0,    0, 0, 0, 0,
                              0, 0, 0xff, 0xff, 0, 0, 0, 1};
  static const u8 our4[16] = {0, 0, 0,    0,    0,  0, 0, 0,
                              0, 0, 0xff, 0xff, 10, 0, 0, 1};
  xdpmac          c;
  u8              mac[6] = {7, 7, 7, 7, 7, 7};
  u8              got[6];
  xdpmac_init(&c);
  xdpmac_learn(&c, v4, mac, our4);
  CHECK(xdpmac_lookup(&c, v4, got, xm_got_our) == 1);
  CHECK(ct_diffn(xm_got_our, our4, 16) == 0);
  CHECK(xdpmac_lookup(&c, xm_ip(0), got, xm_got_our) == 0);
}

void test_xdpmac(void) {
  test_xdpmac_learn_then_lookup();
  test_xdpmac_our_address_and_family();
  test_xdpmac_miss();
  test_xdpmac_relearn_updates();
  test_xdpmac_full_evicts_round_robin();
}
