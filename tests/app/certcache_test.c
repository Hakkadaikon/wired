#include "app/http3/server/certcache/certcache.h"

#include "test.h"
#include "tls/handshake/core/sdrv/sdrv.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/x25519.h"

static void certcache_test_keys(u8 srv_priv[32], u8 srv_pub[32], u8 seed[32]) {
  for (usz i = 0; i < 32; i++) {
    srv_priv[i] = (u8)(0x40 + i);
    seed[i]     = (u8)(0x80 + i);
  }
  wired_x25519_base(srv_pub, srv_priv);
}

/* 1 if the primed cache's DER equals the driver's own certificate bytes. */
static int certcache_test_der_eq(const wired_certcache* c, const quic_sdrv* s) {
  if (c->chain[0].n != s->certs[0].n) return 0;
  for (usz i = 0; i < s->certs[0].n; i++)
    if (c->der[i] != s->certs[0].p[i]) return 0;
  return 1;
}

/* Priming builds byte-identical DER to the per-connection self-signed path
 * (same cert_seed, no SAN, now_secs 0), and rewrites id to the 1-entry
 * cached chain. */
static void test_certcache_prime_matches_sdrv(void) {
  u8                     srv_priv[32], srv_pub[32], seed[32];
  static wired_certcache cache;
  static quic_sdrv       s;
  wired_srvboot_id       id = {0};
  certcache_test_keys(srv_priv, srv_pub, seed);
  id.cert_seed = seed;
  wired_certcache_prime(&cache, &id);
  CHECK(id.chain == cache.chain);
  CHECK(id.chain_count == 1);
  CHECK(cache.chain[0].n != 0);
  {
    quic_sdrv_init_in din = {srv_priv, srv_pub, seed, 0, 0, 0, 0, 0};
    quic_sdrv_init(&s, &din);
  }
  CHECK(s.cert_count == 1);
  CHECK(certcache_test_der_eq(&cache, &s));
}

/* Every init from a primed id holds a view into the cache, not a rebuilt
 * copy -- the per-connection build cost is gone. */
static void test_certcache_primed_init_reuses_der(void) {
  u8                     srv_priv[32], srv_pub[32], seed[32];
  static wired_certcache cache;
  static quic_sdrv       s;
  wired_srvboot_id       id = {0};
  certcache_test_keys(srv_priv, srv_pub, seed);
  id.cert_seed = seed;
  wired_certcache_prime(&cache, &id);
  for (int n = 0; n < 3; n++) {
    quic_sdrv_init_in din = {srv_priv,       srv_pub, seed, id.chain,
                             id.chain_count, 0,       0,    0};
    quic_sdrv_init(&s, &din);
    CHECK(s.cert_count == 1);
    CHECK(s.certs[0].p == cache.der);
  }
}

/* An id carrying an externally issued chain is left untouched and the cache
 * stays unbuilt. */
static void test_certcache_external_chain_noop(void) {
  u8                     seed[32], fake[4] = {1, 2, 3, 4};
  static wired_certcache cache;
  wired_span             ext[1];
  wired_srvboot_id       id = {0};
  for (usz i = 0; i < 32; i++) seed[i] = (u8)(0x80 + i);
  ext[0]         = wired_span_of(fake, 4);
  id.cert_seed   = seed;
  id.chain       = ext;
  id.chain_count = 1;
  wired_certcache_prime(&cache, &id);
  CHECK(id.chain == ext);
  CHECK(id.chain_count == 1);
  CHECK(cache.primed == 0);
}

/* A SAN iPAddress changes the DER, and the SAN-carrying cache still matches
 * the driver building with the same SAN. */
static void test_certcache_san_variant(void) {
  u8                     srv_priv[32], srv_pub[32], seed[32];
  u8                     san[4] = {127, 0, 0, 1};
  static wired_certcache plain, with_san;
  static quic_sdrv       s;
  wired_srvboot_id       id_a = {0}, id_b = {0};
  certcache_test_keys(srv_priv, srv_pub, seed);
  id_a.cert_seed = seed;
  id_b.cert_seed = seed;
  id_b.san_ipv4  = san;
  wired_certcache_prime(&plain, &id_a);
  wired_certcache_prime(&with_san, &id_b);
  CHECK(with_san.chain[0].n != 0);
  {
    int differ = with_san.chain[0].n != plain.chain[0].n;
    for (usz i = 0; !differ && i < plain.chain[0].n; i++)
      if (plain.der[i] != with_san.der[i]) differ = 1;
    CHECK(differ);
  }
  {
    quic_sdrv_init_in din = {srv_priv, srv_pub, seed, 0, 0, san, 0, 0};
    quic_sdrv_init(&s, &din);
  }
  CHECK(certcache_test_der_eq(&with_san, &s));
}

/* Priming twice neither rebuilds nor moves the chain. */
static void test_certcache_prime_idempotent(void) {
  u8                     seed[32];
  static wired_certcache cache;
  wired_srvboot_id       id = {0};
  u8                     first_byte;
  usz                    first_len;
  for (usz i = 0; i < 32; i++) seed[i] = (u8)(0x80 + i);
  id.cert_seed = seed;
  wired_certcache_prime(&cache, &id);
  first_byte = cache.der[0];
  first_len  = cache.chain[0].n;
  wired_certcache_prime(&cache, &id);
  CHECK(id.chain == cache.chain);
  CHECK(id.chain_count == 1);
  CHECK(cache.der[0] == first_byte);
  CHECK(cache.chain[0].n == first_len);
}

/* RFC 6066 3: a driver initialized from the primed chain still matches
 * SNI=localhost -- the cached self-signed certificate carries the same
 * dNSName SAN the per-connection build does. */
static void test_certcache_sni_localhost_match(void) {
  u8       cli_priv[32], cli_pub[32], srv_priv[32], srv_pub[32], seed[32];
  u8       ch[512], srv_random[32];
  const u8 host[] = "localhost";
  usz      ch_len;
  static wired_certcache cache;
  static quic_sdrv       s;
  wired_srvboot_id       id = {0};
  certcache_test_keys(srv_priv, srv_pub, seed);
  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_random[i] = (u8)(0xa0 + i);
  }
  wired_x25519_base(cli_pub, cli_priv);
  id.cert_seed = seed;
  wired_certcache_prime(&cache, &id);
  ch_len = quic_tls_client_hello(
      &(quic_clienthello_in){
          srv_random, cli_pub, wired_span_of(host, sizeof(host) - 1),
          wired_span_of(0, 0)},
      &(wired_obuf){ch, sizeof(ch), 0});
  CHECK(ch_len != 0);
  {
    quic_sdrv_init_in din = {srv_priv,       srv_pub, seed, id.chain,
                             id.chain_count, 0,       0,    0};
    quic_sdrv_init(&s, &din);
  }
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
  CHECK(quic_sdrv_sni_outcome(&s) == QUIC_SALPN_SNI_MATCH);
}

void test_certcache(void) {
  test_certcache_prime_matches_sdrv();
  test_certcache_primed_init_reuses_der();
  test_certcache_external_chain_noop();
  test_certcache_san_variant();
  test_certcache_prime_idempotent();
  test_certcache_sni_localhost_match();
}
