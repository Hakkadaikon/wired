#include "crypto/asymmetric/ecc/cvecdsa/cvecdsa.h"

#include "crypto/asymmetric/ecc/cvecdsa/signed.h"
#include "crypto/asymmetric/ecc/p256/ecdsa_verify.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "test.h"
#include "tls/handshake/core/tls/handshake.h"

/* RFC 6979 A.2.5 keypair: priv X, public point (QX, QY). */
static const char *CV_X =
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
static const char *CV_QX =
    "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
static const char *CV_QY =
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

static void cv_hb32(const char *hex, u8 out[32]) {
  for (usz i = 0; i < 32; i++) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
  }
}

/* A fixed but arbitrary transcript hash. */
static void cv_th(u8 th[32]) {
  for (usz i = 0; i < 32; i++) th[i] = (u8)(i * 7 + 1);
}

/* RFC 8446 4.4.3 signed content: 64*0x20 + ctx + 0x00 + hash. */
static void test_cvecdsa_signed_content(void) {
  u8 th[32], c[130];
  cv_th(th);
  quic_cvecdsa_signed_content(th, c);
  for (usz i = 0; i < 64; i++) CHECK(c[i] == 0x20);
  CHECK(c[64] == 'T' && c[65] == 'L' && c[66] == 'S');
  CHECK(c[97] == 0x00);
  for (usz i = 0; i < 32; i++) CHECK(c[98 + i] == th[i]);
}

/* Message carries handshake type 0x0f and scheme 0x0403, lengths consistent. */
static void test_cvecdsa_header(void) {
  u8  priv[32], th[32], msg[200];
  usz n = 0, body_len = 0;
  u8  type = 0;
  cv_hb32(CV_X, priv);
  cv_th(th);
  CHECK(quic_cvecdsa_build(priv, th, msg, sizeof msg, &n) == 1);
  CHECK(quic_hs_parse(quic_span_of(msg, n), &type, &body_len) == 4);
  CHECK(type == 0x0f);
  CHECK(4 + body_len == n);
  CHECK((((usz)msg[4] << 8) | msg[5]) == 0x0403);
  CHECK((((usz)msg[6] << 8) | msg[7]) == n - 8); /* sig_len == DER length */
}

/* Pull the two 32-byte big-endian scalars out of an ECDSA-Sig-Value DER. */
static void cv_take_int(const u8 *p, u8 out[32]) {
  usz len  = p[1];               /* INTEGER content length */
  usz skip = (len > 32) ? 1 : 0; /* leading 0x00 sign pad */
  usz vlen = len - skip;
  for (usz i = 0; i < 32; i++) out[i] = 0;
  for (usz i = 0; i < vlen; i++) out[32 - vlen + i] = p[2 + skip + i];
}

static void cv_der_extract(const u8 *der, u8 r[32], u8 s[32]) {
  const u8 *rp = der + 2; /* skip SEQ tag + len */
  cv_take_int(rp, r);
  cv_take_int(rp + 2 + rp[1], s); /* next INTEGER after r */
}

/* Verify round-trip: extract DER (r, s), SHA-256 the rebuilt content,
 * confirm the verifier accepts under the matching public key. */
static void test_cvecdsa_verify_roundtrip(void) {
  u8  priv[32], qx[32], qy[32], th[32], msg[200], c[130], h[32];
  u8  r[32], s[32];
  usz n = 0;
  cv_hb32(CV_X, priv);
  cv_hb32(CV_QX, qx);
  cv_hb32(CV_QY, qy);
  cv_th(th);
  CHECK(quic_cvecdsa_build(priv, th, msg, sizeof msg, &n) == 1);
  quic_cvecdsa_signed_content(th, c);
  quic_sha256(c, 130, h);
  /* DER at msg+8: SEQ(0x30) len, INT(0x02) rlen r..., INT(0x02) slen s... */
  cv_der_extract(msg + 8, r, s);
  CHECK(quic_ecdsa_p256_verify(qx, qy, r, s, h) == 1);
}

/* Too-small buffer is rejected. */
static void test_cvecdsa_no_room(void) {
  u8  priv[32], th[32], msg[8];
  usz n = 0;
  cv_hb32(CV_X, priv);
  cv_th(th);
  CHECK(quic_cvecdsa_build(priv, th, msg, sizeof msg, &n) == 0);
}

void test_cvecdsa(void) {
  test_cvecdsa_signed_content();
  test_cvecdsa_header();
  test_cvecdsa_verify_roundtrip();
  test_cvecdsa_no_room();
}
