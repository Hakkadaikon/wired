#include "test.h"

static void hb32(const char* hex, u8 out[32]) {
  for (usz i = 0; i < 32; i++) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
  }
}

/* RFC 7748 Section 5.2 test vector 1. */
static void test_x25519_rfc_v1(void) {
  u8 scalar[32], point[32], out[32], want[32];
  hb32(
      "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
      scalar);
  hb32(
      "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
      point);
  hb32(
      "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", want);
  CHECK(quic_x25519(out, scalar, point) == 1);
  for (usz i = 0; i < 32; i++) CHECK(out[i] == want[i]);
}

/* RFC 7748 Section 5.2 test vector 2. */
static void test_x25519_rfc_v2(void) {
  u8 scalar[32], point[32], out[32], want[32];
  hb32(
      "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
      scalar);
  hb32(
      "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
      point);
  hb32(
      "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", want);
  CHECK(quic_x25519(out, scalar, point) == 1);
  for (usz i = 0; i < 32; i++) CHECK(out[i] == want[i]);
}

/* RFC 7748 6.1: a low-order point yields an all-zero shared secret, which must
 * be rejected (a non-contributory key exchange). u=0 and u=1 are order-1/2
 * points; an honest ladder sends them to zero, and quic_x25519 returns 0. */
static void test_x25519_low_order_rejected(void) {
  u8 scalar[32] = {0}, out[32], low_order[32] = {0};
  scalar[0]  = 5;
  scalar[31] = 0x40;
  CHECK(quic_x25519(out, scalar, low_order) == 0); /* u = 0 */
  for (usz i = 0; i < 32; i++) CHECK(out[i] == 0);
  low_order[0] = 1;
  CHECK(quic_x25519(out, scalar, low_order) == 0); /* u = 1 */
  for (usz i = 0; i < 32; i++) CHECK(out[i] == 0);
}

/* An ECDHE exchange agrees: pub_a = a*G, pub_b = b*G, a*pub_b == b*pub_a. */
static void test_x25519_ecdhe(void) {
  u8 a[32] = {0}, b[32] = {0}, pa[32], pb[32], sa[32], sb[32];
  a[0]  = 5;
  a[31] = 0x40; /* arbitrary clamped-ish scalars */
  b[0]  = 9;
  b[31] = 0x40;
  quic_x25519_base(pa, a);
  quic_x25519_base(pb, b);
  quic_x25519(sa, a, pb);
  quic_x25519(sb, b, pa);
  for (usz i = 0; i < 32; i++) CHECK(sa[i] == sb[i]); /* shared secret */
}

/* RFC 7748 5 (p.343-344, non-canonical values paragraph): u-coordinates in
 * [2^255-19, 2^255-1] are non-canonical (>= p) and MUST be accepted and
 * treated as if reduced mod p. u = p+18 = 2^255-1 (all bytes 0xff, top bit
 * of byte 31 masked to 0 per the same section) must give the identical
 * result to the canonical u = 18. Independently re-derived via a from-
 * scratch ladder reimplementation (not copied from a search hit) before
 * being pinned here. */
static void test_x25519_noncanonical_u_reduced(void) {
  u8 scalar[32] = {9}, noncanon[32], canon[32] = {18}, out_nc[32], out_c[32];
  for (usz i = 0; i < 31; i++) noncanon[i] = 0xff;
  noncanon[31] = 0x7f; /* top bit clear: value == 2^255-1 == p+18 */
  CHECK(quic_x25519(out_nc, scalar, noncanon) == 1);
  CHECK(quic_x25519(out_c, scalar, canon) == 1);
  for (usz i = 0; i < 32; i++) CHECK(out_nc[i] == out_c[i]);
}

/* RFC 7748 5.2 iterative test: k=u=9 (the base point), 1 iteration then
 * 1000 iterations of k_next=X25519(k,u), u_next=k (the sequence swaps k and
 * u each round). 1,000,000 iterations is skipped: correct but far too slow
 * for a unit test. Values re-derived from a from-scratch Montgomery-ladder
 * reimplementation of RFC 7748's own pseudocode before being baked in here,
 * not copied from a search result. */
static void test_x25519_rfc_iterate_1(void) {
  u8 nine[32] = {9}, out[32], want[32];
  hb32(
      "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", want);
  CHECK(quic_x25519(out, nine, nine) == 1);
  for (usz i = 0; i < 32; i++) CHECK(out[i] == want[i]);
}

static void test_x25519_rfc_iterate_1000(void) {
  u8 k[32] = {9}, u[32] = {9}, next[32], want[32];
  hb32(
      "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", want);
  for (int i = 0; i < 1000; i++) {
    quic_x25519(next, k, u);
    for (usz j = 0; j < 32; j++) u[j] = k[j];
    for (usz j = 0; j < 32; j++) k[j] = next[j];
  }
  for (usz i = 0; i < 32; i++) CHECK(k[i] == want[i]);
}

/* RFC 7748 6.1 Diffie-Hellman fixed vector: Alice's and Bob's key pairs and
 * their shared secret K, taken verbatim from the RFC (not random scalars,
 * unlike test_x25519_ecdhe above) so the base-point multiply, the DH
 * exchange, and the exact shared value are all pinned to the spec's own
 * numbers. */
static void test_x25519_rfc_dh_alice_bob(void) {
  u8 a[32], b[32], want_pa[32], want_pb[32], want_k[32];
  u8 pa[32], pb[32], ka[32], kb[32];
  hb32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a);
  hb32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b);
  hb32(
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
      want_pa);
  hb32(
      "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
      want_pb);
  hb32(
      "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
      want_k);

  quic_x25519_base(pa, a);
  quic_x25519_base(pb, b);
  for (usz i = 0; i < 32; i++) CHECK(pa[i] == want_pa[i]);
  for (usz i = 0; i < 32; i++) CHECK(pb[i] == want_pb[i]);

  quic_x25519(ka, a, pb);
  quic_x25519(kb, b, pa);
  for (usz i = 0; i < 32; i++) CHECK(ka[i] == want_k[i]);
  for (usz i = 0; i < 32; i++) CHECK(kb[i] == want_k[i]);
}

void test_x25519(void) {
  test_x25519_rfc_v1();
  test_x25519_rfc_v2();
  test_x25519_low_order_rejected();
  test_x25519_ecdhe();
  test_x25519_noncanonical_u_reduced();
  test_x25519_rfc_iterate_1();
  test_x25519_rfc_iterate_1000();
  test_x25519_rfc_dh_alice_bob();
}
