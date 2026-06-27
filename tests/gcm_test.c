#include "test.h"

/* Parse hex of arbitrary even length into out; returns byte count. */
static usz unhex(const char *hex, u8 *out)
{
    usz i = 0;
    while (hex[i * 2] != 0) {
        u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
        out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                      (lo <= '9' ? lo - '0' : lo - 'a' + 10));
        i++;
    }
    return i;
}

/* NIST SP 800-38D test case 4 (AES-128-GCM with AAD). */
static void test_gcm_nist(void)
{
    u8 key[16], iv[12], pt[64], aad[32], want_ct[64], want_tag[16];
    u8 ct[64], tag[16];
    quic_aes128 a;
    u8 ivbuf[16];
    unhex("feffe9928665731c6d6a8f9467308308", key);
    unhex("cafebabefacedbaddecaf888", ivbuf);
    for (usz i = 0; i < 12; i++) iv[i] = ivbuf[i];
    usz pl = unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d"
                   "8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657"
                   "ba637b39", pt);
    usz al = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad);
    unhex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
          "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", want_ct);
    unhex("5bc94fbc3221a5db94fae95ae7121a47", want_tag);

    quic_aes128_init(&a, key);
    quic_gcm_seal(&a, iv, aad, al, pt, pl, ct, tag);
    for (usz i = 0; i < pl; i++) CHECK(ct[i] == want_ct[i]);
    for (usz i = 0; i < 16; i++) CHECK(tag[i] == want_tag[i]);
}

/* Round-trip plus tamper detection (prover: AUTH_FAIL leaves pt untouched). */
static void test_gcm_open(void)
{
    u8 key[16] = {0}, iv[12] = {0};
    u8 pt[20], ct[20], dec[20], tag[16];
    quic_aes128 a;
    for (usz i = 0; i < 20; i++) { pt[i] = (u8)i; dec[i] = 0xCC; }
    quic_aes128_init(&a, key);
    quic_gcm_seal(&a, iv, (const u8 *)"hdr", 3, pt, 20, ct, tag);

    CHECK(quic_gcm_open(&a, iv, (const u8 *)"hdr", 3, ct, 20, tag, dec) == 1);
    for (usz i = 0; i < 20; i++) CHECK(dec[i] == pt[i]);

    /* flip one tag bit: must reject and not overwrite dec */
    for (usz i = 0; i < 20; i++) dec[i] = 0xCC;
    u8 bad[16];
    for (usz i = 0; i < 16; i++) bad[i] = tag[i];
    bad[0] ^= 1;
    CHECK(quic_gcm_open(&a, iv, (const u8 *)"hdr", 3, ct, 20, bad, dec) == 0);
    for (usz i = 0; i < 20; i++) CHECK(dec[i] == 0xCC);

    /* flip one AAD byte: must reject */
    CHECK(quic_gcm_open(&a, iv, (const u8 *)"HDR", 3, ct, 20, tag, dec) == 0);
}

void test_gcm(void)
{
    test_gcm_nist();
    test_gcm_open();
}
