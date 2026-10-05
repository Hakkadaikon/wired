#include <string.h>
#include <unistd.h>

#include "app/http3/server/srvboot/srvdemo.h"
#include "test.h"
#include "tls/handshake/core/tls/x25519.h"

/* The counting pattern the guide samples (base 0x50) and examples (0x40)
 * hard-coded before this helper existed. */
static void test_srvboot_demo_pattern(void) {
  static wired_srvboot_demo_keys k;
  wired_srvboot_id               id;
  u8                             pub[32];
  memset(&id, 0xee, sizeof id);
  wired_srvboot_demo(&id, &k, 0x50, "guide-h3");
  CHECK(k.priv[0] == 0x50 && k.priv[31] == 0x6f);
  CHECK(k.seed[0] == 0x90 && k.seed[31] == 0xaf);
  CHECK(k.rnd[0] == 0xb0 && k.rnd[31] == 0xcf);
  wired_x25519_base(pub, k.priv);
  CHECK(memcmp(pub, k.pub, 32) == 0);
  CHECK(id.priv == k.priv && id.pub == k.pub);
  CHECK(id.cert_seed == k.seed && id.random == k.rnd);
  CHECK(id.scid_len == 8 && memcmp(id.scid, "guide-h3", 8) == 0);
}

/* Every other field is reset: self-signed, defaults, no DATAGRAM. */
static void test_srvboot_demo_zeroes_rest(void) {
  static wired_srvboot_demo_keys k;
  wired_srvboot_id               id;
  memset(&id, 0xee, sizeof id);
  wired_srvboot_demo(&id, &k, 0x40, "CLISCI");
  CHECK(k.priv[0] == 0x40 && k.seed[0] == 0x80 && k.rnd[0] == 0xa0);
  CHECK(id.chain == 0 && id.chain_count == 0 && id.max_data == 0);
  CHECK(id.max_datagram_frame_size == 0 && id.san_ipv4 == 0);
  CHECK(id.now_secs == 0 && id.scid_len == 6);
}

/* Boundary: a connection id longer than 20 bytes (RFC 9000 17.2) is cut. */
static void test_srvboot_demo_scid_cap(void) {
  static wired_srvboot_demo_keys k;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &k, 0x50, "0123456789abcdefghijKLMN");
  CHECK(id.scid_len == 20);
  wired_srvboot_demo(&id, &k, 0x50, "");
  CHECK(id.scid_len == 0);
}

void test_srvboot_demo(void) {
  test_srvboot_demo_pattern();
  test_srvboot_demo_zeroes_rest();
  test_srvboot_demo_scid_cap();
}

/* An external chain's fingerprint is SHA-256 of its leaf as given: leaf
 * "abc" -> the FIPS 180-2 B.1 digest. */
static void test_srvboot_cert_sha256_chain(void) {
  static wired_srvboot_demo_keys k;
  static const u8  want[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                               0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                               0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                               0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
  wired_span       leaf     = wired_span_of((const u8*)"abc", 3);
  wired_srvboot_id id;
  u8               fp[32];
  wired_srvboot_demo(&id, &k, 0x50, "guide-wt");
  id.chain       = &leaf;
  id.chain_count = 1;
  CHECK(wired_srvboot_cert_sha256(&id, fp));
  CHECK(memcmp(fp, want, 32) == 0);
}

/* Self-signed: deterministic per identity, and a different signing seed
 * yields a different certificate. */
static void test_srvboot_cert_sha256_selfsigned(void) {
  static wired_srvboot_demo_keys k1, k2;
  wired_srvboot_id               a, b;
  u8                             f1[32], f2[32], f3[32];
  wired_srvboot_demo(&a, &k1, 0x50, "guide-wt");
  wired_srvboot_demo(&b, &k2, 0x40, "guide-wt");
  CHECK(wired_srvboot_cert_sha256(&a, f1) && wired_srvboot_cert_sha256(&a, f2));
  CHECK(wired_srvboot_cert_sha256(&b, f3));
  CHECK(memcmp(f1, f2, 32) == 0 && memcmp(f1, f3, 32) != 0);
}

/* The log line is the colon form browsers / openssl print. */
static void test_srvboot_log_fingerprint(void) {
  static wired_srvboot_demo_keys k;
  static char                    got[256];
  wired_span                     leaf = wired_span_of((const u8*)"abc", 3);
  wired_srvboot_id               id;
  int                            fds[2];
  wired_srvboot_demo(&id, &k, 0x50, "guide-wt");
  id.chain       = &leaf;
  id.chain_count = 1;
  CHECK(pipe(fds) == 0);
  CHECK(wired_srvboot_log_fingerprint(fds[1], &id));
  ssz n              = read(fds[0], got, sizeof got - 1);
  got[n < 0 ? 0 : n] = 0;
  CHECK(
      strcmp(
          got,
          "cert sha-256 fingerprint: ba:78:16:bf:8f:01:cf:ea:41:41:40:"
          "de:5d:ae:22:23:b0:03:61:a3:96:17:7a:9c:b4:10:ff:61:f2:00:15:ad\n") ==
      0);
  close(fds[0]);
  close(fds[1]);
}

void test_srvboot_cert_sha256(void) {
  test_srvboot_log_fingerprint();
  test_srvboot_cert_sha256_chain();
  test_srvboot_cert_sha256_selfsigned();
}
