#include "app/http3/server/certcache/certcache.h"

#include "crypto/asymmetric/ecc/p256/p256_field.h"
#include "crypto/asymmetric/ecc/p256/p256_point.h"
#include "crypto/pki/cert/p256cert/p256cert.h"

/* RFC 5280 4.2.1.6: 0 unless ip is a non-null, non-zero IPv4 address --
 * all-zero is the "no SAN requested" sentinel (0.0.0.0 is never a real
 * peer), matching the per-connection build's own treatment. */
static int certcache_san_nonzero(const u8* ip) {
  int nonzero = 0;
  for (usz i = 0; i < 4; i++) nonzero |= ip[i];
  return nonzero;
}

static const u8* certcache_san(const u8* ip) {
  if (!ip) return 0;
  return certcache_san_nonzero(ip) ? ip : 0;
}

/* RFC 5480 / RFC 5280 4.1: derive the public key from id->cert_seed and
 * build the self-signed certificate DER into c -- the same construction the
 * per-connection self-signed path performs, so the bytes are identical. */
static void certcache_build(wired_certcache* c, const wired_srvboot_id* id) {
  ec_point q;
  u8       pub_x[32], pub_y[32];
  ec_mul(&q, id->cert_seed, &p256_g);
  p256_fp_to_be(pub_x, q.x);
  p256_fp_to_be(pub_y, q.y);
  {
    p256cert_key k = {
        id->cert_seed, pub_x, pub_y, certcache_san(id->san_ipv4), id->now_secs};
    wired_obuf o = obuf_of(c->der, sizeof(c->der));
    p256cert_build(&k, &o);
    c->chain[0] = wired_span_of(c->der, o.len);
  }
  c->primed = 1;
}

void wired_certcache_prime(wired_certcache* c, wired_srvboot_id* id) {
  if (id->chain_count != 0) return;
  if (!c->primed) certcache_build(c, id);
  id->chain       = c->chain;
  id->chain_count = 1;
}
