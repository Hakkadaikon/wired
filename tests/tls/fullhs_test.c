#include "tls/handshake/core/fullhs/fullhs.h"

#include "crypto/asymmetric/ecc/ed25519/ed25519.h"
#include "crypto/pki/cert/selfcert/selfcert.h"
#include "test.h"
#include "tls/handshake/core/tls/cert.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/hs_message.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/roles/sflight/certmsg.h"
#include "tls/handshake/roles/sflight/certverify_build.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"

/* Minimal ServerHello (RFC 8446 4.1.3) carrying x25519 key_share pub. */
static usz fullhs_build_sh(u8* out, usz cap, const u8 pub[32]) {
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

static usz fullhs_wrap_crypto(u8* out, usz cap, const u8* msg, usz n) {
  usz                        w   = 0;
  quic_obuf                  ob  = quic_obuf_of(out, cap);
  quic_crypto_stream_emit_in ein = {0, 256};
  CHECK(quic_crypto_stream_emit(quic_span_of(msg, n), &ein, &ob) == 1);
  w = ob.len;
  return w;
}

/* Drive both tlsdriver sides to the handshake secret over real ECDHE, and
 * hand back the real ServerHello bytes exchanged (sh, *shn) -- the same
 * message quic_fullhs_init must seed its transcript with (RFC 8446 4.4.1),
 * not some unrelated fixed constant. */
static void reach_hs_secret(
    quic_tlsdriver* cl, quic_tlsdriver* sv, const u8 sv_pub[32], u8* sh,
    usz* shn) {
  u8  frame[1024];
  usz fl;
  {
    quic_obuf ob = quic_obuf_of(frame, sizeof(frame));
    CHECK(quic_tlsdriver_client_hello(cl, &ob) == 1);
    fl = ob.len;
  }
  CHECK(quic_tlsdriver_recv_crypto(sv, frame, fl) == 1);
  *shn = fullhs_build_sh(sh, 512, sv_pub);
  fl   = fullhs_wrap_crypto(frame, sizeof(frame), sh, *shn);
  CHECK(quic_tlsdriver_recv_crypto(cl, frame, fl) == 1);
  CHECK(quic_tlsdriver_handshake_secret_ready(cl) == 1);
  CHECK(quic_tlsdriver_handshake_secret_ready(sv) == 1);
}

/* A freshly built self-signed Ed25519 leaf, wrapped as a TLS Certificate
 * message (RFC 8446 4.4.2) -- built once per test from seed, not a golden
 * constant, so its signature always matches whatever transcript this run's
 * real ClientHello/ServerHello exchange produced. */
static usz build_cert_msg(const u8 seed[32], u8* out, usz cap) {
  u8        der[512];
  quic_obuf dob = quic_obuf_of(der, sizeof(der));
  quic_obuf mob = quic_obuf_of(out, cap);
  CHECK(quic_selfcert_build(seed, &dob) == 1);
  CHECK(quic_sflight_certificate(quic_span_of(der, dob.len), &mob) == 1);
  return mob.len;
}

/* Feed a freshly signed Certificate + CertificateVerify (over h's own
 * current transcript hash, RFC 8446 4.4.3) to one fullhs side. cert_msg is
 * built once by the caller and shared by both sides (the same leaf every
 * peer sees); the CertificateVerify signature is recomputed per h, since
 * each side's transcript hash through Certificate is its own running state
 * even though both transcripts hold the identical bytes. */
static void feed_auth(
    quic_fullhs* h, const u8 seed[32], const u8* cert_msg, usz cert_msg_len) {
  u8        th[QUIC_SHA256_DIGEST];
  u8        cv[256];
  quic_obuf cvob = quic_obuf_of(cv, sizeof(cv));
  CHECK(quic_fullhs_recv_cert(h, cert_msg, cert_msg_len) == 1);
  quic_sha256(h->tr, h->tr_len, th);
  CHECK(quic_sflight_certificate_verify(seed, th, &cvob) == 1);
  CHECK(
      quic_fullhs_recv_certverify(
          h, quic_span_of(cv, cvob.len), QUIC_TLS_SCHEME_ED25519) == 1);
}

/* Wrap quic_fullhs_send_finished's obuf triple for CHECK-friendly call sites.
 */
static int send_fin(quic_fullhs* h, u8* out, usz cap, usz* out_len) {
  quic_obuf ob = quic_obuf_of(out, cap);
  int       ok = quic_fullhs_send_finished(h, &ob);
  *out_len     = ob.len;
  return ok;
}

/* RFC 8446 4.4 / RFC 9001 4.1: a full handshake reaches complete on both
 * sides, derives the application secret, installs the 1-RTT keys, confirms,
 * and discards the Handshake keys. */
static void test_fullhs_e2e(void) {
  u8                       cl_priv[32], cl_pub[32], sv_priv[32], sv_pub[32];
  u8                       cert_seed[32], sh[512], svfin[64], clfin[64];
  u8                       cert_msg[768];
  usz                      shn, cert_msg_len, n;
  quic_tlsdriver           cltls, svtls;
  quic_fullhs              cl, sv;
  const quic_initial_keys* k;

  for (usz i = 0; i < 32; i++) {
    cl_priv[i]   = (u8)(1 + i);
    sv_priv[i]   = (u8)(200 - i);
    cert_seed[i] = (u8)(50 + i);
  }
  quic_x25519_base(cl_pub, cl_priv);
  quic_x25519_base(sv_pub, sv_priv);
  quic_tlsdriver_init(&cltls, cl_priv, cl_pub, 0);
  quic_tlsdriver_init(&svtls, sv_priv, sv_pub, 1);
  reach_hs_secret(&cltls, &svtls, sv_pub, sh, &shn);

  CHECK(quic_fullhs_init(&cl, &cltls, quic_span_of(sh, shn)) == 1);
  CHECK(quic_fullhs_init(&sv, &svtls, quic_span_of(sh, shn)) == 1);

  cert_msg_len = build_cert_msg(cert_seed, cert_msg, sizeof(cert_msg));

  /* server authenticates itself into its own transcript, then signs Finished */
  feed_auth(&sv, cert_seed, cert_msg, cert_msg_len);
  CHECK(send_fin(&sv, svfin, sizeof(svfin), &n) == 1);

  /* client receives Certificate, CertificateVerify, server Finished */
  feed_auth(&cl, cert_seed, cert_msg, cert_msg_len);
  CHECK(quic_fullhs_recv_finished(&cl, svfin, n) == 1);
  CHECK(quic_fullhs_is_complete(&cl) == 1);

  /* server completes by receiving the client's Finished */
  CHECK(send_fin(&cl, clfin, sizeof(clfin), &n) == 1);
  CHECK(quic_fullhs_recv_finished(&sv, clfin, n) == 1);
  CHECK(quic_fullhs_is_complete(&sv) == 1);

  /* both derive the application secret and install 1-RTT keys */
  CHECK(quic_fullhs_advance_application(&cl) == 1);
  CHECK(quic_fullhs_advance_application(&sv) == 1);
  CHECK(quic_keyset_for_level(&cltls.keys, QUIC_LEVEL_ONERTT, &k) == 1);
  CHECK(quic_keyset_for_level(&svtls.keys, QUIC_LEVEL_ONERTT, &k) == 1);

  /* HANDSHAKE_DONE confirms and discards the Handshake keys */
  CHECK(quic_keyset_for_level(&cltls.keys, QUIC_LEVEL_HANDSHAKE, &k) == 1);
  CHECK(quic_fullhs_confirmed(&cl) == 1);
  CHECK(quic_fullhs_is_confirmed(&cl) == 1);
  CHECK(quic_keyset_for_level(&cltls.keys, QUIC_LEVEL_HANDSHAKE, &k) == 0);
}

/* RFC 8446 4.4.3: a bad CertificateVerify signature keeps the auth gate shut,
 * so the server's Finished is never accepted and the handshake never completes.
 */
static void test_fullhs_bad_certverify(void) {
  u8             cl_priv[32], cl_pub[32], sv_priv[32], sv_pub[32];
  u8             cert_seed[32], sh[512], cert_msg[768];
  u8             th[QUIC_SHA256_DIGEST], cv[256];
  quic_obuf      cvob = quic_obuf_of(cv, sizeof(cv));
  usz            shn, cert_msg_len;
  quic_tlsdriver cltls, svtls;
  quic_fullhs    cl;

  for (usz i = 0; i < 32; i++) {
    cl_priv[i]   = (u8)(1 + i);
    sv_priv[i]   = (u8)(200 - i);
    cert_seed[i] = (u8)(50 + i);
  }
  quic_x25519_base(cl_pub, cl_priv);
  quic_x25519_base(sv_pub, sv_priv);
  quic_tlsdriver_init(&cltls, cl_priv, cl_pub, 0);
  quic_tlsdriver_init(&svtls, sv_priv, sv_pub, 1);
  reach_hs_secret(&cltls, &svtls, sv_pub, sh, &shn);
  CHECK(quic_fullhs_init(&cl, &cltls, quic_span_of(sh, shn)) == 1);

  cert_msg_len = build_cert_msg(cert_seed, cert_msg, sizeof(cert_msg));
  CHECK(quic_fullhs_recv_cert(&cl, cert_msg, cert_msg_len) == 1);
  quic_sha256(cl.tr, cl.tr_len, th);
  CHECK(quic_sflight_certificate_verify(cert_seed, th, &cvob) == 1);
  cv[QUIC_HS_HEADER + 4] ^= 0x01; /* corrupt the R||S signature bytes */

  CHECK(
      quic_fullhs_recv_certverify(
          &cl, quic_span_of(cv, cvob.len), QUIC_TLS_SCHEME_ED25519) == 0);
  CHECK(quic_fullhs_is_complete(&cl) == 0);
}

/* RFC 8446 4.4.4: a tampered Finished verify_data is rejected and the
 * handshake stays incomplete. */
static void test_fullhs_bad_finished(void) {
  u8             cl_priv[32], cl_pub[32], sv_priv[32], sv_pub[32];
  u8             cert_seed[32], sh[512], cert_msg[768], svfin[64];
  usz            shn, cert_msg_len, n;
  quic_tlsdriver cltls, svtls;
  quic_fullhs    cl, sv;

  for (usz i = 0; i < 32; i++) {
    cl_priv[i]   = (u8)(1 + i);
    sv_priv[i]   = (u8)(200 - i);
    cert_seed[i] = (u8)(50 + i);
  }
  quic_x25519_base(cl_pub, cl_priv);
  quic_x25519_base(sv_pub, sv_priv);
  quic_tlsdriver_init(&cltls, cl_priv, cl_pub, 0);
  quic_tlsdriver_init(&svtls, sv_priv, sv_pub, 1);
  reach_hs_secret(&cltls, &svtls, sv_pub, sh, &shn);
  CHECK(quic_fullhs_init(&cl, &cltls, quic_span_of(sh, shn)) == 1);
  CHECK(quic_fullhs_init(&sv, &svtls, quic_span_of(sh, shn)) == 1);

  cert_msg_len = build_cert_msg(cert_seed, cert_msg, sizeof(cert_msg));
  feed_auth(&sv, cert_seed, cert_msg, cert_msg_len);
  CHECK(send_fin(&sv, svfin, sizeof(svfin), &n) == 1);
  feed_auth(&cl, cert_seed, cert_msg, cert_msg_len);

  svfin[QUIC_HS_HEADER] ^= 0x01; /* corrupt verify_data */
  CHECK(quic_fullhs_recv_finished(&cl, svfin, n) == 0);
  CHECK(quic_fullhs_is_complete(&cl) == 0);
}

void test_fullhs(void) {
  test_fullhs_e2e();
  test_fullhs_bad_certverify();
  test_fullhs_bad_finished();
}
