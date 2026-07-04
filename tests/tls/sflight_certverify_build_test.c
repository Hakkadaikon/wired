#include "crypto/asymmetric/ecc/ed25519/ed25519.h"
#include "test.h"
#include "tls/handshake/core/tls/cert.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/roles/sflight/certverify_build.h"

/* RFC 8446 4.4.3: rebuild the signed content (64*0x20 + context + 0x00 +
 * transcript_hash) and confirm the built signature verifies under the seed's
 * public key. */
static void rebuild_signed(const u8* thash, u8 out[130]) {
  static const char ctx[] = "TLS 1.3, server CertificateVerify";
  for (usz i = 0; i < 64; i++) out[i] = 0x20;
  for (usz i = 0; i < 33; i++) out[64 + i] = (u8)ctx[i];
  out[97] = 0x00;
  for (usz i = 0; i < 32; i++) out[98 + i] = thash[i];
}

void test_sflight_certverify_build(void) {
  u8        seed[32], pub[32], content[130];
  u8        thash[32];
  u8        out[80];
  usz       body_len;
  u8        type;
  u16       scheme;
  quic_span sig;
  quic_obuf ob = quic_obuf_of(out, sizeof(out));

  for (usz i = 0; i < 32; i++) seed[i] = (u8)(i + 7);
  for (usz i = 0; i < 32; i++) thash[i] = (u8)(0x40 + i);
  CHECK(quic_ed25519_keypair(seed, pub));

  CHECK(quic_sflight_certificate_verify(seed, thash, &ob));
  CHECK(quic_hs_parse(quic_span_of(out, ob.len), &type, &body_len) == 4);
  CHECK(type == 15);
  CHECK(4 + body_len == ob.len);

  /* body parses as scheme 0x0807 + a 64-byte signature. */
  CHECK(quic_tls_certverify_parse(
      quic_span_of(out + 4, body_len), &scheme, &sig));
  CHECK(scheme == 0x0807);
  CHECK(sig.n == 64);

  /* the signature verifies over the RFC 8446 4.4.3 signed content. */
  rebuild_signed(thash, content);
  CHECK(quic_ed25519_verify(sig.p, content, 130, pub));

  /* a tampered transcript hash must not verify. */
  content[129] ^= 0x01;
  CHECK(!quic_ed25519_verify(sig.p, content, 130, pub));

  ob = quic_obuf_of(out, 4);
  CHECK(!quic_sflight_certificate_verify(seed, thash, &ob));
}
