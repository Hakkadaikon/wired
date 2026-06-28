#include "test.h"
#include "sdrv/sdrv.h"
#include "tls/clienthello.h"
#include "tls/serverhello.h"
#include "tls/cert.h"
#include "tls/certverify.h"
#include "tls/finished.h"
#include "tls/handshake.h"
#include "tls/schedule.h"
#include "tls/x25519.h"
#include "ed25519/ed25519.h"

/* RFC 8446 4 / RFC 9001 4: a client emits a ClientHello, the server driver
 * builds the real server flight, and the client reaches the same ECDHE shared
 * secret, verifies the CertificateVerify signature against the server's
 * Ed25519 certificate, and checks the Finished. */

/* RFC 5280 4.1: a minimal Ed25519 end-entity certificate carrying pub in its
 * subjectPublicKeyInfo. The five tbs fields before the SPKI are empty
 * placeholders the verifier skips; only the SPKI is read. */
static usz build_ed_cert(u8 *out, const u8 pub[32])
{
    static const u8 head[] = {
        0x30, 0x48,                   /* Certificate SEQUENCE, len 0x48 */
        0x30, 0x3c,                   /* tbsCertificate SEQUENCE, len 0x3c */
        0xa0, 0x03, 0x02, 0x01, 0x02, /* [0] version v3 */
        0x02, 0x01, 0x01,             /* serialNumber INTEGER 1 */
        0x30, 0x00,                   /* signature AlgorithmIdentifier (empty) */
        0x30, 0x00,                   /* issuer (empty) */
        0x30, 0x00,                   /* validity (empty) */
        0x30, 0x00,                   /* subject (empty) */
        0x30, 0x2a,                   /* SPKI SEQUENCE, len 0x2a */
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, /* AlgId { OID 1.3.101.112 } */
        0x03, 0x21, 0x00,             /* BIT STRING, 33 bytes, 0 unused bits */
    };
    static const u8 tail[] = {
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, /* signatureAlgorithm OID */
        0x03, 0x01, 0x00,             /* signatureValue BIT STRING (empty) */
    };
    usz off = 0, i;
    for (i = 0; i < sizeof(head); i++) out[off++] = head[i];
    for (i = 0; i < 32; i++) out[off++] = pub[i];
    for (i = 0; i < sizeof(tail); i++) out[off++] = tail[i];
    return off;
}

/* Split the server flight (EE || Cert || CertVerify || Finished) into its four
 * messages by walking the 4-byte handshake headers. */
static int next_hs(const u8 *b, usz n, usz *p, const u8 **msg, usz *len)
{
    usz body;
    u8 type;
    if (*p + 4 > n) return 0;
    if (quic_hs_parse(b + *p, n - *p, &type, &body) != 4) return 0;
    *msg = b + *p;
    *len = 4 + body;
    *p += *len;
    return 1;
}

void test_sdrv(void)
{
    u8 cli_priv[32], cli_pub[32], srv_priv[32], srv_pub[32];
    u8 cert_seed[32], cert_pub[32], cert[128];
    u8 ch[512], sh[256], flight[2048];
    u8 srv_random[32], shared_cli[32], hs[32], s_traffic[32], th[32];
    u8 sh_pub[32];
    u16 cipher, version;
    usz cert_len, ch_len, sh_len, hs_len, p = 0;
    const u8 *ee, *cm, *cv, *fin, *srv_hs_secret;
    usz eel, cml, cvl, finl;
    u16 cv_scheme, cv_siglen;
    const u8 *cv_sig;
    quic_sdrv s;

    for (usz i = 0; i < 32; i++) {
        cli_priv[i] = (u8)(i + 1);
        srv_priv[i] = (u8)(0x40 + i);
        cert_seed[i] = (u8)(0x80 + i);
        srv_random[i] = (u8)(0xa0 + i);
    }
    quic_x25519_base(cli_pub, cli_priv);
    quic_x25519_base(srv_pub, srv_priv);
    CHECK(quic_ed25519_keypair(cert_seed, cert_pub));
    cert_len = build_ed_cert(cert, cert_pub);

    /* client: emit a ClientHello carrying its x25519 key_share. */
    {
        static const u8 tp[1] = {0};
        ch_len = quic_tls_client_hello(ch, sizeof(ch), srv_random, cli_pub,
                                       0, 0, tp, sizeof(tp));
    }
    CHECK(ch_len != 0);

    /* server: drive the flight. */
    quic_sdrv_init(&s, srv_priv, srv_pub, cert_seed, cert, cert_len);
    CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
    CHECK(quic_sdrv_build_server_flight(&s, srv_random, sh, sizeof(sh), &sh_len,
                                        flight, sizeof(flight), &hs_len));

    /* client: parse ServerHello and reach the same ECDHE shared secret. */
    CHECK(quic_tls_parse_server_hello(sh, sh_len, sh_pub, &cipher, &version));
    CHECK(cipher == 0x1301);
    CHECK(version == 0x0304);
    quic_x25519(shared_cli, cli_priv, sh_pub);

    /* both derive the same handshake secret from the shared ECDHE. */
    quic_tls_handshake_secret(shared_cli, hs);
    CHECK(quic_sdrv_handshake_secret(&s, &srv_hs_secret));
    for (usz i = 0; i < 32; i++) CHECK(hs[i] == srv_hs_secret[i]);

    /* split the flight into its four messages. */
    CHECK(next_hs(flight, hs_len, &p, &ee, &eel));
    CHECK(next_hs(flight, hs_len, &p, &cm, &cml));
    CHECK(next_hs(flight, hs_len, &p, &cv, &cvl));
    CHECK(next_hs(flight, hs_len, &p, &fin, &finl));
    CHECK(ee[0] == 0x08 && cm[0] == 0x0b && cv[0] == 0x0f && fin[0] == 0x14);

    /* CertificateVerify verifies against the server's Ed25519 certificate over
     * the transcript through Certificate (ClientHello..Certificate). */
    {
        quic_transcript tr;
        quic_transcript_init(&tr);
        quic_transcript_add(&tr, ch, ch_len);
        quic_transcript_add(&tr, sh, sh_len);
        quic_transcript_add(&tr, ee, eel);
        quic_transcript_add(&tr, cm, cml);
        quic_transcript_hash(&tr, th);
    }
    CHECK(quic_tls_certverify_parse(cv + 4, cvl - 4, &cv_scheme, &cv_sig,
                                    &cv_siglen));
    CHECK(cv_scheme == 0x0807);
    CHECK(quic_tls_verify_cert_signature(0x0807, cert, cert_len, cv_sig,
                                         cv_siglen, th));

    /* Finished verifies under the server handshake traffic secret (derived
     * over the transcript through ServerHello) at the transcript hash through
     * CertificateVerify. */
    {
        quic_transcript tr;
        u8 fin_th[32];
        quic_transcript_init(&tr);
        quic_transcript_add(&tr, ch, ch_len);
        quic_transcript_add(&tr, sh, sh_len);
        quic_transcript_hash(&tr, fin_th); /* through ServerHello */
        quic_hkdf_expand_label(hs, "s hs traffic", 12, fin_th, 32, s_traffic, 32);
        quic_transcript_add(&tr, ee, eel);
        quic_transcript_add(&tr, cm, cml);
        quic_transcript_add(&tr, cv, cvl);
        quic_transcript_hash(&tr, fin_th); /* through CertificateVerify */
        CHECK(quic_tls_finished_check(s_traffic, fin_th, fin + 4));
    }
}
