#include "transport/io/xdp/xdpmac/xdpmac.h"

#include "test.h"

/* Distinct network-order keys 1..n and per-key MACs for the fill tests. */
static u32 xm_ip(u32 n) { return 0x0a000000u | (n + 1); }

static void xm_mac(u32 n, u8 out[6]) {
  for (u32 i = 0; i < 6; i++) out[i] = (u8)(n + i);
}

/* learn then lookup returns 1 and the learned MAC. */
static void test_xdpmac_learn_then_lookup(void) {
  quic_xdpmac c;
  u8          mac[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
  u8          got[6] = {0};
  quic_xdpmac_init(&c);
  quic_xdpmac_learn(&c, xm_ip(0), mac);
  CHECK(quic_xdpmac_lookup(&c, xm_ip(0), got) == 1);
  for (u32 i = 0; i < 6; i++) CHECK(got[i] == mac[i]);
}

/* an ip never learned misses (0), and mac_out is untouched. */
static void test_xdpmac_miss(void) {
  quic_xdpmac c;
  u8          got[6] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
  quic_xdpmac_init(&c);
  CHECK(quic_xdpmac_lookup(&c, xm_ip(0), got) == 0);
  for (u32 i = 0; i < 6; i++) CHECK(got[i] == 0x55);
}

/* re-learning the same ip updates the MAC in place (no second slot). */
static void test_xdpmac_relearn_updates(void) {
  quic_xdpmac c;
  u8          a[6] = {1, 1, 1, 1, 1, 1};
  u8          b[6] = {2, 2, 2, 2, 2, 2};
  u8          got[6];
  quic_xdpmac_init(&c);
  quic_xdpmac_learn(&c, xm_ip(0), a);
  quic_xdpmac_learn(&c, xm_ip(0), b);
  CHECK(quic_xdpmac_lookup(&c, xm_ip(0), got) == 1);
  for (u32 i = 0; i < 6; i++) CHECK(got[i] == 2);
}

/* 64 entries fill the cache; the 65th evicts round-robin: the oldest (first
 * learned) is gone, the newest and every other entry are still present. */
static void test_xdpmac_full_evicts_round_robin(void) {
  quic_xdpmac c;
  u8          mac[6];
  u8          got[6];
  quic_xdpmac_init(&c);
  for (u32 n = 0; n < QUIC_XDPMAC_CAP + 1; n++) {
    xm_mac(n, mac);
    quic_xdpmac_learn(&c, xm_ip(n), mac);
  }
  CHECK(quic_xdpmac_lookup(&c, xm_ip(0), got) == 0); /* oldest evicted */
  CHECK(quic_xdpmac_lookup(&c, xm_ip(QUIC_XDPMAC_CAP), got) == 1); /* newest */
  CHECK(got[0] == (u8)QUIC_XDPMAC_CAP);
  for (u32 n = 1; n < QUIC_XDPMAC_CAP; n++)
    CHECK(quic_xdpmac_lookup(&c, xm_ip(n), got) == 1); /* survivors intact */
}

void test_xdpmac(void) {
  test_xdpmac_learn_then_lookup();
  test_xdpmac_miss();
  test_xdpmac_relearn_updates();
  test_xdpmac_full_evicts_round_robin();
}
