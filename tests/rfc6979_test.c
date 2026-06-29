#include "test.h"
#include "p256sign/rfc6979.h"

static void r6979_hb32(const char *hex, u8 out[32])
{
    for (usz i = 0; i < 32; i++) {
        u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
        out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                      (lo <= '9' ? lo - '0' : lo - 'a' + 10));
    }
}

/* RFC 6979 Appendix A.2.5: P-256, SHA-256, message "sample". */
static const char *R6979_X = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
static const char *R6979_K = "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60";

static void test_rfc6979_sample_k(void)
{
    u8 priv[32], want[32], h[32], k[32];
    r6979_hb32(R6979_X, priv);
    r6979_hb32(R6979_K, want);
    quic_sha256((const u8 *)"sample", 6, h);
    quic_p256sign_k(priv, h, k);
    for (usz i = 0; i < 32; i++) CHECK(k[i] == want[i]);
}

void test_rfc6979(void)
{
    test_rfc6979_sample_k();
}
