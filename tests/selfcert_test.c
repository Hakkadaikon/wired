#include "test.h"
#include "selfcert/selfcert.h"
#include "selfcert/tbs.h"
#include "selfcert/derenc.h"
#include "asn1/der.h"
#include "x509/x509.h"
#include "x509/spki.h"
#include "ed25519/ed25519.h"

/* X.690 8.1. der_tlv emits a well-formed TLV that der_read parses back. */
static void test_der_tlv_roundtrip(void)
{
    u8 out[8];
    usz n;
    const u8 v[] = {0xaa, 0xbb};
    CHECK(quic_selfcert_der_tlv(QUIC_DER_INTEGER, v, 2, out, sizeof(out), &n) == 1);
    CHECK(n == 4 && out[0] == 0x02 && out[1] == 0x02);

    u8 tag;
    const u8 *val;
    usz vlen, used;
    CHECK(quic_der_read(out, n, &tag, &val, &vlen, &used) == 1);
    CHECK(tag == 0x02 && vlen == 2 && val[0] == 0xaa && val[1] == 0xbb);
}

/* X.690 8.1.3.5. A 200-octet value uses the 0x81 long form. */
static void test_der_tlv_longform(void)
{
    u8 big[200] = {0};
    u8 out[210];
    usz n;
    CHECK(quic_selfcert_der_tlv(QUIC_DER_OCTET_STRING, big, 200, out, sizeof(out), &n) == 1);
    CHECK(out[1] == 0x81 && out[2] == 200 && n == 203);
}

/* der_tlv refuses to overflow the caller buffer. */
static void test_der_tlv_overflow(void)
{
    u8 out[3];
    usz n;
    const u8 v[] = {1, 2, 3, 4};
    CHECK(quic_selfcert_der_tlv(QUIC_DER_INTEGER, v, 4, out, sizeof(out), &n) == 0);
}

/* RFC 8410 4. The built SPKI exposes the same 32-byte Ed25519 key. */
static void test_tbs_spki_key(void)
{
    u8 pub[32];
    u8 seed[32];
    for (usz i = 0; i < 32; i++) seed[i] = (u8)i;
    CHECK(quic_ed25519_keypair(seed, pub) == 1);

    u8 tbs[512];
    usz tn;
    CHECK(quic_selfcert_tbs(pub, tbs, sizeof(tbs), &tn) == 1);

    const u8 *oid, *key;
    usz oid_len, key_len;
    CHECK(quic_x509_public_key(tbs, tn, &oid, &oid_len, &key, &key_len) == 1);
    /* BIT STRING value: 0x00 unused-bits prefix then the 32-byte key. */
    CHECK(key_len == 33 && key[0] == 0x00);
    for (usz i = 0; i < 32; i++) CHECK(key[1 + i] == pub[i]);
}

/* RFC 5280 4.1.1.3. Parse the cert back and verify its own signature. */
static void test_build_selfsigned(void)
{
    u8 seed[32];
    for (usz i = 0; i < 32; i++) seed[i] = (u8)(0x40 + i);
    u8 pub[32];
    quic_ed25519_keypair(seed, pub);

    u8 cert[1024];
    usz clen;
    CHECK(quic_selfcert_build(seed, cert, sizeof(cert), &clen) == 1);

    quic_x509 c;
    CHECK(quic_x509_parse(cert, clen, &c) == 1);

    const u8 *oid, *key;
    usz oid_len, key_len;
    CHECK(quic_x509_public_key(c.tbs, c.tbs_len, &oid, &oid_len, &key, &key_len) == 1);
    CHECK(key_len == 33);
    for (usz i = 0; i < 32; i++) CHECK(key[1 + i] == pub[i]);

    /* signatureValue BIT STRING: 0x00 prefix then the 64-byte signature. */
    CHECK(c.sig_len == 65 && c.sig[0] == 0x00);
    CHECK(quic_ed25519_verify(c.sig + 1, c.tbs, c.tbs_len, key + 1) == 1);

    /* A flipped TBS byte must break verification. */
    u8 bad = c.tbs[0];
    ((u8 *)c.tbs)[0] ^= 0xff;
    CHECK(quic_ed25519_verify(c.sig + 1, c.tbs, c.tbs_len, key + 1) == 0);
    ((u8 *)c.tbs)[0] = bad;
}

void test_selfcert(void)
{
    test_der_tlv_roundtrip();
    test_der_tlv_longform();
    test_der_tlv_overflow();
    test_tbs_spki_key();
    test_build_selfsigned();
}
