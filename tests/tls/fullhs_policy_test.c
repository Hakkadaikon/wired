#include "crypto/asymmetric/ecc/p256/p256_field.h"
#include "crypto/asymmetric/ecc/p256/p256_point.h"
#include "crypto/pki/cert/p256cert/p256cert.h"
#include "fullhs_golden.h"
#include "test.h"
#include "tls/handshake/core/fullhs/fullhs.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/hs_message.h"
#include "tls/handshake/core/tls/x25519.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"

/* Minimal ServerHello (RFC 8446 4.1.3) carrying an x25519 key_share pub. */
static usz fp_build_sh(u8* out, usz cap, const u8 pub[32]) {
  usz off      = quic_hs_begin(out, cap, 2), block;
  out[off]     = 0x03;
  out[off + 1] = 0x03;
  for (usz i = 0; i < 32; i++) out[off + 2 + i] = (u8)(0x10 + i);
  out[off + 34] = 0;
  out[off + 35] = 0x13;
  out[off + 36] = 0x01;
  out[off + 37] = 0;
  block         = off + 38;
  off           = block + 2;
  out[off]      = 0x00;
  out[off + 1]  = 0x2b;
  out[off + 2]  = 0x00;
  out[off + 3]  = 2;
  out[off + 4]  = 0x03;
  out[off + 5]  = 0x04;
  off += 6;
  out[off]     = 0x00;
  out[off + 1] = 0x33;
  out[off + 2] = 0x00;
  out[off + 3] = 36;
  out[off + 4] = 0x00;
  out[off + 5] = 0x1d;
  out[off + 6] = 0x00;
  out[off + 7] = 32;
  for (usz i = 0; i < 32; i++) out[off + 8 + i] = pub[i];
  off += 40;
  out[block]     = (u8)((off - block - 2) >> 8);
  out[block + 1] = (u8)(off - block - 2);
  quic_hs_finish(out, off);
  (void)cap;
  return off;
}

/* CertificateVerify: type(15) len(3) | scheme(2) | sig(2+len). */
static usz fp_build_cv(u8* out, u16 scheme, const u8* sig, usz sig_len) {
  usz body = 4 + sig_len;
  out[0]   = 0x0f;
  out[1]   = 0;
  out[2]   = (u8)(body >> 8);
  out[3]   = (u8)body;
  out[4]   = (u8)(scheme >> 8);
  out[5]   = (u8)scheme;
  out[6]   = (u8)(sig_len >> 8);
  out[7]   = (u8)sig_len;
  for (usz i = 0; i < sig_len; i++) out[8 + i] = sig[i];
  return 4 + body;
}

/* Drive fresh client/server tlsdrivers to the handshake secret and seed the
 * client fullhs from the golden transcript. */
static void fp_new_client(
    quic_tlsdriver* cl, quic_tlsdriver* sv, quic_fullhs* h) {
  u8  cl_priv[32], cl_pub[32], sv_priv[32], sv_pub[32];
  u8  frame[1024], sh[512];
  usz fl, shn;
  for (usz i = 0; i < 32; i++) {
    cl_priv[i] = (u8)(1 + i);
    sv_priv[i] = (u8)(200 - i);
  }
  quic_x25519_base(cl_pub, cl_priv);
  quic_x25519_base(sv_pub, sv_priv);
  quic_tlsdriver_init(cl, cl_priv, cl_pub, 0);
  quic_tlsdriver_init(sv, sv_priv, sv_pub, 1);
  {
    quic_obuf ob = quic_obuf_of(frame, sizeof(frame));
    CHECK(quic_tlsdriver_client_hello(cl, &ob) == 1);
    fl = ob.len;
  }
  CHECK(quic_tlsdriver_recv_crypto(sv, frame, fl) == 1);
  shn = fp_build_sh(sh, sizeof(sh), sv_pub);
  {
    quic_obuf                  ob  = quic_obuf_of(frame, sizeof(frame));
    quic_crypto_stream_emit_in ein = {0, 256};
    CHECK(quic_crypto_stream_emit(quic_span_of(sh, shn), &ein, &ob) == 1);
    fl = ob.len;
  }
  CHECK(quic_tlsdriver_recv_crypto(cl, frame, fl) == 1);
  CHECK(
      quic_fullhs_init(h, cl, quic_span_of(fullhs_sh, sizeof(fullhs_sh))) == 1);
}

/* quic_fullhs_recv_cert under the given policy, on a fresh client. */
static int fp_cert_result(
    u64 now, const u8* host, usz host_len, const u8* msg, usz msg_len) {
  quic_tlsdriver cl, sv;
  quic_fullhs    h;
  fp_new_client(&cl, &sv, &h);
  quic_fullhs_set_policy(&h, now, quic_span_of(host, host_len));
  return quic_fullhs_recv_cert(&h, msg, msg_len);
}

/* Wrap one DER cert in a Certificate message (RFC 8446 4.4.2):
 * type(0x0b) len(3) | ctx(1)=0 | list(3) | cert(3) | cert | exts(2)=0. */
static usz fp_wrap_cert(u8* out, const u8* cert, usz n) {
  usz body = n + 9;
  out[0]   = 0x0b;
  out[1]   = (u8)(body >> 16);
  out[2]   = (u8)(body >> 8);
  out[3]   = (u8)body;
  out[4]   = 0;
  out[5]   = (u8)((n + 5) >> 16);
  out[6]   = (u8)((n + 5) >> 8);
  out[7]   = (u8)(n + 5);
  out[8]   = (u8)(n >> 16);
  out[9]   = (u8)(n >> 8);
  out[10]  = (u8)n;
  for (usz i = 0; i < n; i++) out[11 + i] = cert[i];
  out[11 + n] = 0;
  out[12 + n] = 0;
  return 13 + n;
}

/* A self-signed P-256 cert (SAN dNSName "localhost", validity 2020..2030)
 * wrapped in a Certificate message. */
static usz fp_p256_cert_msg(u8* msg) {
  u8       priv[32], x[32], y[32], cert[600];
  usz      clen;
  ec_point q;
  for (usz i = 0; i < 32; i++) priv[i] = (u8)(3 + i);
  quic_ec_mul(&q, priv, &quic_p256_g);
  quic_fp_to_be(x, q.x);
  quic_fp_to_be(y, q.y);
  quic_p256cert_key k = {priv, x, y, 0, 0};
  quic_obuf         o = quic_obuf_of(cert, sizeof(cert));
  CHECK(quic_p256cert_build(&k, &o) == 1);
  clen = o.len;
  return fp_wrap_cert(msg, cert, clen);
}

/* RFC 5280 6.1: the golden cert (2026..2036) is accepted inside its window
 * and rejected after notAfter and before notBefore. */
static void test_fullhs_policy_validity(void) {
  const u8* m = fullhs_cert_msg;
  usz       n = sizeof(fullhs_cert_msg);
  CHECK(fp_cert_result(20270101000000ULL, 0, 0, m, n) == 1);
  CHECK(fp_cert_result(20370101000000ULL, 0, 0, m, n) == 0);
  CHECK(fp_cert_result(20200101000000ULL, 0, 0, m, n) == 0);
}

/* RFC 6125: a hostname policy against a cert with no SAN rejects (no CN
 * fallback). */
static void test_fullhs_policy_no_san(void) {
  CHECK(
      fp_cert_result(
          0, (const u8*)"other.example", 13, fullhs_cert_msg,
          sizeof(fullhs_cert_msg)) == 0);
}

/* RFC 6125: SAN dNSName match accepts, mismatch rejects, and a combined
 * policy needs both the name and the window to hold. */
static void test_fullhs_policy_san(void) {
  u8  msg[640];
  usz n = fp_p256_cert_msg(msg);
  CHECK(fp_cert_result(0, (const u8*)"localhost", 9, msg, n) == 1);
  CHECK(fp_cert_result(0, (const u8*)"evil.example", 12, msg, n) == 0);
  CHECK(
      fp_cert_result(20260702000000ULL, (const u8*)"localhost", 9, msg, n) ==
      1);
  CHECK(
      fp_cert_result(20310101000000ULL, (const u8*)"localhost", 9, msg, n) ==
      0);
}

/* A policy reject at Certificate time keeps the auth gate shut: even the
 * valid golden CertificateVerify and a correctly signed server Finished are
 * refused afterwards, so the handshake can never complete. */
static void test_fullhs_policy_gate(void) {
  quic_tlsdriver cltls, svtls;
  quic_fullhs    cl, sv;
  u8             cv[256], svfin[64];
  usz            cv_len, n;

  fp_new_client(&cltls, &svtls, &cl);
  CHECK(
      quic_fullhs_init(
          &sv, &svtls, quic_span_of(fullhs_sh, sizeof(fullhs_sh))) == 1);
  quic_fullhs_set_policy(
      &cl, 20370101000000ULL, quic_span_of(0, 0)); /* expired */

  cv_len = fp_build_cv(
      cv, QUIC_TLS_SCHEME_ED25519, fullhs_cv_sig, sizeof(fullhs_cv_sig));
  /* the server (no policy) authenticates itself and signs its Finished */
  CHECK(
      quic_fullhs_recv_cert(&sv, fullhs_cert_msg, sizeof(fullhs_cert_msg)) ==
      1);
  CHECK(
      quic_fullhs_recv_certverify(
          &sv, quic_span_of(cv, cv_len), QUIC_TLS_SCHEME_ED25519) == 1);
  {
    quic_obuf ob = quic_obuf_of(svfin, sizeof(svfin));
    CHECK(quic_fullhs_send_finished(&sv, &ob) == 1);
    n = ob.len;
  }

  /* the client rejects the cert; CV and Finished must both fail after it */
  CHECK(
      quic_fullhs_recv_cert(&cl, fullhs_cert_msg, sizeof(fullhs_cert_msg)) ==
      0);
  CHECK(
      quic_fullhs_recv_certverify(
          &cl, quic_span_of(cv, cv_len), QUIC_TLS_SCHEME_ED25519) == 0);
  CHECK(quic_fullhs_recv_finished(&cl, svfin, n) == 0);
  CHECK(quic_fullhs_is_complete(&cl) == 0);
}

void test_fullhs_policy(void) {
  test_fullhs_policy_validity();
  test_fullhs_policy_no_san();
  test_fullhs_policy_san();
  test_fullhs_policy_gate();
}
