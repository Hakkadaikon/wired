#include "test.h"
#include "client/client.h"
#include "tls/x25519.h"
#include "tls/handshake.h"
#include "tls/hsdriver.h"
#include "tls/certverify.h"
#include "crypto_stream/crypto_tx.h"
#include "fullhs_golden.h"

/* Minimal ServerHello (RFC 8446 4.1.3) carrying an x25519 key_share pub. */
static usz client_build_sh(u8 *out, usz cap, const u8 pub[32])
{
    usz off = quic_hs_begin(out, cap, 2), block;
    out[off] = 0x03; out[off + 1] = 0x03;
    for (usz i = 0; i < 32; i++) out[off + 2 + i] = (u8)(0x10 + i);
    out[off + 34] = 0;
    out[off + 35] = 0x13; out[off + 36] = 0x01;
    out[off + 37] = 0;
    block = off + 38;
    off = block + 2;
    out[off] = 0x00; out[off + 1] = 0x2b;
    out[off + 2] = 0x00; out[off + 3] = 2;
    out[off + 4] = 0x03; out[off + 5] = 0x04;
    off += 6;
    out[off] = 0x00; out[off + 1] = 0x33;
    out[off + 2] = 0x00; out[off + 3] = 36;
    out[off + 4] = 0x00; out[off + 5] = 0x1d;
    out[off + 6] = 0x00; out[off + 7] = 32;
    for (usz i = 0; i < 32; i++) out[off + 8 + i] = pub[i];
    off += 40;
    out[block] = (u8)((off - block - 2) >> 8);
    out[block + 1] = (u8)(off - block - 2);
    quic_hs_finish(out, off);
    (void)cap;
    return off;
}

/* CertificateVerify: type(15) len(3) | scheme(2) | sig(2+len). */
static usz client_build_cv(u8 *out, u16 scheme, const u8 *sig, usz sig_len)
{
    usz body = 4 + sig_len;
    out[0] = 0x0f;
    out[1] = 0; out[2] = (u8)(body >> 8); out[3] = (u8)body;
    out[4] = (u8)(scheme >> 8); out[5] = (u8)scheme;
    out[6] = (u8)(sig_len >> 8); out[7] = (u8)sig_len;
    for (usz i = 0; i < sig_len; i++) out[8 + i] = sig[i];
    return 4 + body;
}

/* Drive a client tlsdriver and a server tlsdriver to the shared handshake
 * secret over real ECDHE (mirror of the on-wire CH/SH exchange). */
static void client_reach_hs_secret(quic_tlsdriver *cl, quic_tlsdriver *sv,
                                   const u8 sv_pub[32])
{
    u8 frame[1024], sh[256];
    usz fl, shn;
    CHECK(quic_tlsdriver_client_hello(cl, frame, sizeof(frame), &fl) == 1);
    CHECK(quic_tlsdriver_recv_crypto(sv, frame, fl) == 1);
    shn = client_build_sh(sh, sizeof(sh), sv_pub);
    CHECK(quic_crypto_stream_emit(sh, shn, 0, 256, frame, sizeof(frame), &fl) == 1);
    CHECK(quic_tlsdriver_recv_crypto(cl, frame, fl) == 1);
    CHECK(quic_tlsdriver_handshake_secret_ready(cl) == 1);
}

/* RFC 9000 14.1: the Initial built by start is padded to 1200 bytes. */
static void test_client_initial_padded(void)
{
    u8 cl_priv[32], cl_pub[32], dg[QUIC_CLIENT_DATAGRAM_MAX];
    quic_client c;
    usz len;
    for (usz i = 0; i < 32; i++) cl_priv[i] = (u8)(7 + i);
    quic_x25519_base(cl_pub, cl_priv);
    quic_tlsdriver_init(&c.tls, cl_priv, cl_pub, 0);
    len = quic_client_build_initial(&c, dg, sizeof(dg));
    CHECK(len == 1200);
}

/* RFC 9001 4.1: feeding a real ServerHello advances INITIAL -> AUTH. */
static void test_client_feed_serverhello(void)
{
    u8 cl_priv[32], cl_pub[32], sv_priv[32], sv_pub[32], sh[256], frame[1024];
    quic_client c;
    quic_tlsdriver svtls;
    usz shn, fl;

    for (usz i = 0; i < 32; i++) { cl_priv[i] = (u8)(1 + i); sv_priv[i] = (u8)(200 - i); }
    quic_x25519_base(cl_pub, cl_priv);
    quic_x25519_base(sv_pub, sv_priv);
    quic_tlsdriver_init(&c.tls, cl_priv, cl_pub, 0);
    c.phase = QUIC_CLIENT_HS_INITIAL;
    c.sh_len = 0;
    quic_tlsdriver_init(&svtls, sv_priv, sv_pub, 1);
    CHECK(quic_tlsdriver_client_hello(&c.tls, frame, sizeof(frame), &fl) == 1);
    CHECK(quic_tlsdriver_recv_crypto(&svtls, frame, fl) == 1);

    shn = client_build_sh(sh, sizeof(sh), sv_pub);
    CHECK(quic_crypto_stream_emit(sh, shn, 0, 256, frame, sizeof(frame), &fl) == 1);
    CHECK(quic_client_feed(&c, frame, fl) == 1);
    CHECK(c.phase == QUIC_CLIENT_HS_AUTH);
}

/* RFC 8446 4.4 / RFC 9001 4.1: client_run_handshake reaches confirmed by
 * feeding Certificate, CertificateVerify and the server Finished (no socket). */
static void test_client_e2e_confirmed(void)
{
    quic_client c;
    quic_fullhs sv;
    quic_tlsdriver svtls;
    u8 cv[256], svfin[64];
    u8 cl_priv[32], cl_pub[32], sv_priv[32], sv_pub[32];
    usz cv_len, n;

    for (usz i = 0; i < 32; i++) { cl_priv[i] = (u8)(1 + i); sv_priv[i] = (u8)(200 - i); }
    quic_x25519_base(cl_pub, cl_priv);
    quic_x25519_base(sv_pub, sv_priv);
    quic_tlsdriver_init(&c.tls, cl_priv, cl_pub, 0);
    quic_tlsdriver_init(&svtls, sv_priv, sv_pub, 1);

    /* both sides agree the same ECDHE secret, then fix fullhs to the golden
     * transcript so the golden CV/Finished verify on both. */
    client_reach_hs_secret(&c.tls, &svtls, sv_pub);
    CHECK(quic_tlsdriver_handshake_secret_ready(&svtls) == 1);
    CHECK(quic_fullhs_init(&c.hs, &c.tls, fullhs_sh, sizeof(fullhs_sh)) == 1);
    CHECK(quic_fullhs_init(&sv, &svtls, fullhs_sh, sizeof(fullhs_sh)) == 1);
    c.phase = QUIC_CLIENT_HS_AUTH;
    c.fd = -1;

    /* server authenticates itself and signs its Finished. */
    cv_len = client_build_cv(cv, QUIC_TLS_SCHEME_ED25519, fullhs_cv_sig,
                             sizeof(fullhs_cv_sig));
    CHECK(quic_fullhs_recv_cert(&sv, fullhs_cert_msg, sizeof(fullhs_cert_msg)) == 1);
    CHECK(quic_fullhs_recv_certverify(&sv, cv, cv_len, QUIC_TLS_SCHEME_ED25519) == 1);
    CHECK(quic_fullhs_send_finished(&sv, svfin, sizeof(svfin), &n) == 1);

    /* client consumes the server's auth flight via feed; reaches confirmed. */
    CHECK(quic_client_feed(&c, fullhs_cert_msg, sizeof(fullhs_cert_msg)) == 1);
    CHECK(quic_client_feed(&c, cv, cv_len) == 1);
    CHECK(quic_client_feed(&c, svfin, n) == 1);
    CHECK(quic_client_is_connected(&c) == 1);
}

void test_client(void)
{
    test_client_initial_padded();
    test_client_feed_serverhello();
    test_client_e2e_confirmed();
}
