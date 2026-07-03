#include "castore_golden.h"
#include "fullhs_golden.h"
#include "realchain_golden.h"
#include "test.h"
#include "tls/handshake/core/fullhs/fullhs.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/hs_message.h"
#include "tls/handshake/core/tls/x25519.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"

/* Minimal ServerHello (RFC 8446 4.1.3) carrying an x25519 key_share pub. */
static usz fc_build_sh(u8 *out, usz cap, const u8 pub[32]) {
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
static usz fc_build_cv(u8 *out, u16 scheme, const u8 *sig, usz sig_len) {
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

/* Fresh client tlsdriver at the handshake secret, fullhs seeded from the
 * golden transcript. */
static void fc_new_client(
    quic_tlsdriver *cl, quic_tlsdriver *sv, quic_fullhs *h) {
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
  shn = fc_build_sh(sh, sizeof(sh), sv_pub);
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

/* A Certificate handshake message wrapping k DER certs, leaf first. */
static usz fc_cert_msg(
    u8 *out, const u8 *const *certs, const usz *lens, usz k) {
  usz off = QUIC_HS_HEADER + 4, list, body;
  for (usz i = 0; i < k; i++) {
    usz n        = lens[i];
    out[off]     = (u8)(n >> 16);
    out[off + 1] = (u8)(n >> 8);
    out[off + 2] = (u8)n;
    for (usz j = 0; j < n; j++) out[off + 3 + j] = certs[i][j];
    out[off + 3 + n] = 0;
    out[off + 4 + n] = 0;
    off += n + 5;
  }
  list                    = off - QUIC_HS_HEADER - 4;
  body                    = list + 4;
  out[0]                  = 0x0b;
  out[1]                  = (u8)(body >> 16);
  out[2]                  = (u8)(body >> 8);
  out[3]                  = (u8)body;
  out[QUIC_HS_HEADER]     = 0; /* request context */
  out[QUIC_HS_HEADER + 1] = (u8)(list >> 16);
  out[QUIC_HS_HEADER + 2] = (u8)(list >> 8);
  out[QUIC_HS_HEADER + 3] = (u8)list;
  return off;
}

static const u8 *fc_realchain[2]     = {0, 0}; /* set in test entry */
static usz       fc_realchain_len[2] = {0, 0};

/* T-006: after recv_cert the caller's buffer may die; the recorded cert must
 * live in the transcript, so the golden CertificateVerify still verifies. */
static void test_fullhs_chain_stale_buffer(void) {
  quic_tlsdriver cltls, svtls;
  quic_fullhs    cl;
  u8             buf[sizeof(fullhs_cert_msg)], cv[256];
  usz            cv_len;
  fc_new_client(&cltls, &svtls, &cl);
  for (usz i = 0; i < sizeof(buf); i++) buf[i] = fullhs_cert_msg[i];
  CHECK(quic_fullhs_recv_cert(&cl, buf, sizeof(buf)) == 1);
  for (usz i = 0; i < sizeof(buf); i++) buf[i] = 0xaa; /* buffer dies */
  cv_len = fc_build_cv(
      cv, QUIC_TLS_SCHEME_ED25519, fullhs_cv_sig, sizeof(fullhs_cv_sig));
  CHECK(
      quic_fullhs_recv_certverify(
          &cl, quic_span_of(cv, cv_len), QUIC_TLS_SCHEME_ED25519) == 1);
}

/* T-007: a [leaf, intermediate] message is fully retained: both certs are
 * viewable from the transcript and byte-equal to the wire DER. */
static void test_fullhs_chain_retained(void) {
  quic_tlsdriver cltls, svtls;
  quic_fullhs    cl;
  u8             msg[1024];
  usz            n;
  fc_new_client(&cltls, &svtls, &cl);
  n = fc_cert_msg(msg, fc_realchain, fc_realchain_len, 2);
  CHECK(quic_fullhs_recv_cert(&cl, msg, n) == 1);
  CHECK(cl.cert_count == 2);
  CHECK(cl.cert_lens[0] == sizeof(quic_realchain_leaf_der));
  CHECK(cl.cert_lens[1] == sizeof(quic_realchain_int_der));
  for (usz i = 0; i < cl.cert_lens[0]; i++)
    CHECK(cl.tr[cl.cert_off[0] + i] == quic_realchain_leaf_der[i]);
  for (usz i = 0; i < cl.cert_lens[1]; i++)
    CHECK(cl.tr[cl.cert_off[1] + i] == quic_realchain_int_der[i]);
  CHECK(cl.peer_cert == cl.tr + cl.cert_off[0]);
}

/* T-008: with the right root in the store, [leaf, int] is accepted (the
 * public-web shape: the root itself is not on the wire). */
static void test_fullhs_castore_ok(void) {
  quic_tlsdriver     cltls, svtls;
  quic_fullhs        cl;
  quic_castore       store;
  quic_castore_entry roots[2];
  u8                 msg[1024];
  usz                n;
  fc_new_client(&cltls, &svtls, &cl);
  quic_castore_init(&store, roots, 2);
  CHECK(
      quic_castore_add(
          &store,
          quic_span_of(
              quic_realchain_root_der, sizeof(quic_realchain_root_der))) == 1);
  quic_fullhs_set_castore(&cl, &store);
  n = fc_cert_msg(msg, fc_realchain, fc_realchain_len, 2);
  CHECK(quic_fullhs_recv_cert(&cl, msg, n) == 1);
}

/* T-009: a store without the chain's root rejects the Certificate, and the
 * auth gate stays shut for the valid CV and a correctly signed Finished. */
static void test_fullhs_castore_wrong_root(void) {
  quic_tlsdriver     cltls, svtls;
  quic_fullhs        cl, sv;
  quic_castore       store;
  quic_castore_entry roots[2];
  u8                 cv[256], svfin[64];
  usz                cv_len, n;
  fc_new_client(&cltls, &svtls, &cl);
  CHECK(
      quic_fullhs_init(
          &sv, &svtls, quic_span_of(fullhs_sh, sizeof(fullhs_sh))) == 1);
  quic_castore_init(&store, roots, 2);
  CHECK(
      quic_castore_add(
          &store,
          quic_span_of(
              quic_realchain_root_der, sizeof(quic_realchain_root_der))) == 1);
  quic_fullhs_set_castore(&cl, &store); /* golden cert can't anchor here */

  cv_len = fc_build_cv(
      cv, QUIC_TLS_SCHEME_ED25519, fullhs_cv_sig, sizeof(fullhs_cv_sig));
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

  CHECK(
      quic_fullhs_recv_cert(&cl, fullhs_cert_msg, sizeof(fullhs_cert_msg)) ==
      0);
  CHECK(
      quic_fullhs_recv_certverify(
          &cl, quic_span_of(cv, cv_len), QUIC_TLS_SCHEME_ED25519) == 0);
  CHECK(quic_fullhs_recv_finished(&cl, svfin, n) == 0);
  CHECK(quic_fullhs_is_complete(&cl) == 0);
}

/* T-010: a wire chain in the wrong order ([int, leaf]) breaks the links. */
static void test_fullhs_castore_swapped(void) {
  quic_tlsdriver     cltls, svtls;
  quic_fullhs        cl;
  quic_castore       store;
  quic_castore_entry roots[2];
  const u8 *certs[2] = {quic_realchain_int_der, quic_realchain_leaf_der};
  usz       lens[2]  = {
      sizeof(quic_realchain_int_der), sizeof(quic_realchain_leaf_der)};
  u8  msg[1024];
  usz n;
  fc_new_client(&cltls, &svtls, &cl);
  quic_castore_init(&store, roots, 2);
  CHECK(
      quic_castore_add(
          &store,
          quic_span_of(
              quic_realchain_root_der, sizeof(quic_realchain_root_der))) == 1);
  quic_fullhs_set_castore(&cl, &store);
  n = fc_cert_msg(msg, certs, lens, 2);
  CHECK(quic_fullhs_recv_cert(&cl, msg, n) == 0);
}

void test_fullhs_chain(void) {
  fc_realchain[0]     = quic_realchain_leaf_der;
  fc_realchain[1]     = quic_realchain_int_der;
  fc_realchain_len[0] = sizeof(quic_realchain_leaf_der);
  fc_realchain_len[1] = sizeof(quic_realchain_int_der);
  test_fullhs_chain_stale_buffer();
  test_fullhs_chain_retained();
  test_fullhs_castore_ok();
  test_fullhs_castore_wrong_root();
  test_fullhs_castore_swapped();
}
