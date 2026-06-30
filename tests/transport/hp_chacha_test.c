#include "test.h"

static void hpc_uhx(const char *hex, u8 *out, usz n)
{
    for (usz i = 0; i < n; i++) {
        u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
        out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                      (lo <= '9' ? lo - '0' : lo - 'a' + 10));
    }
}

/* RFC 9001 A.5: ChaCha20-Poly1305 Short Header Packet header-protection. */
void test_hp_chacha(void)
{
    u8 hpkey[32], sample[16], mask[5], want[5];
    hpc_uhx("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
            hpkey, 32);
    hpc_uhx("5e5cd55c41f69080575d7999c25a5bfb", sample, 16);
    quic_hp_chacha_mask(hpkey, sample, mask);
    hpc_uhx("aefefe7d03", want, 5);
    for (usz i = 0; i < 5; i++) CHECK(mask[i] == want[i]);
}
